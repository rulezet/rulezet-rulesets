rule Arcane_cystack_c003336d
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_c003336d"

    strings:
        $key_0 = "AdapterRAM:" ascii
        $key_1 = "Capacity:" ascii
        $key_2 = "Caption:" ascii
        $key_3 = "ChassisTypes:" ascii
        $key_4 = "Description:" ascii
        $key_5 = "DeviceID:" ascii
        $key_6 = "FileSystem:" ascii
        $key_7 = "FreeSpace:" ascii
        $key_8 = "FullName:" ascii
        $key_9 = "IPEnabled:" ascii
        $key_10 = "Internal IP:" ascii
        $key_11 = "MACAddress:" ascii
        $key_12 = "Manufacturer:" ascii
        $key_13 = "MaxClockSpeed:" ascii
        $key_14 = "Model:" ascii
        $key_15 = "Name:" ascii
        $key_16 = "NumberOfCores:" ascii
        $key_17 = "OSArchitecture:" ascii
        $key_18 = "Product:" ascii
        $key_19 = "ReleaseDate:" ascii
        $key_20 = "SMBIOSBIOSVersion:" ascii
        $key_21 = "SerialNumber:" ascii
        $key_22 = "Size:" ascii
        $key_23 = "Speed:" ascii
        $key_24 = "Version:" ascii

    condition:
        all of ($key_*)
}