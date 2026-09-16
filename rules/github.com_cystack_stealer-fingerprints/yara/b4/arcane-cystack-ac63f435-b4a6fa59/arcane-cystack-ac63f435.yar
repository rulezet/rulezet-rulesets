rule Arcane_cystack_ac63f435
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_ac63f435"

    strings:
        $key_0 = "AdapterRAM:" ascii
        $key_1 = "Capacity:" ascii
        $key_2 = "Caption:" ascii
        $key_3 = "ChassisTypes:" ascii
        $key_4 = "Default:" ascii
        $key_5 = "Description:" ascii
        $key_6 = "DeviceID:" ascii
        $key_7 = "FileSystem:" ascii
        $key_8 = "FreeSpace:" ascii
        $key_9 = "FullName:" ascii
        $key_10 = "IPEnabled:" ascii
        $key_11 = "Internal IP:" ascii
        $key_12 = "MACAddress:" ascii
        $key_13 = "Manufacturer:" ascii
        $key_14 = "MaxClockSpeed:" ascii
        $key_15 = "Model:" ascii
        $key_16 = "Name:" ascii
        $key_17 = "NumberOfCores:" ascii
        $key_18 = "OSArchitecture:" ascii
        $key_19 = "Product:" ascii
        $key_20 = "ReleaseDate:" ascii
        $key_21 = "SMBIOSBIOSVersion:" ascii
        $key_22 = "SerialNumber:" ascii
        $key_23 = "Size:" ascii
        $key_24 = "Speed:" ascii
        $key_25 = "Version:" ascii

    condition:
        all of ($key_*)
}