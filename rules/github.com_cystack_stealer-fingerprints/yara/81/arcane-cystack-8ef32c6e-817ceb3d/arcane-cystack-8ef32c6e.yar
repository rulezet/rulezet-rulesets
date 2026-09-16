rule Arcane_cystack_8ef32c6e
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_8ef32c6e"

    strings:
        $key_0 = "AdapterRAM:" ascii
        $key_1 = "Capacity:" ascii
        $key_2 = "Caption:" ascii
        $key_3 = "ChassisTypes:" ascii
        $key_4 = "Default:" ascii
        $key_5 = "Description:" ascii
        $key_6 = "DeviceID:" ascii
        $key_7 = "External IP:" ascii
        $key_8 = "FileSystem:" ascii
        $key_9 = "FreeSpace:" ascii
        $key_10 = "FullName:" ascii
        $key_11 = "Gateway IP:" ascii
        $key_12 = "IPEnabled:" ascii
        $key_13 = "MACAddress:" ascii
        $key_14 = "Manufacturer:" ascii
        $key_15 = "MaxClockSpeed:" ascii
        $key_16 = "Model:" ascii
        $key_17 = "Name:" ascii
        $key_18 = "NumberOfCores:" ascii
        $key_19 = "OSArchitecture:" ascii
        $key_20 = "Product:" ascii
        $key_21 = "ReleaseDate:" ascii
        $key_22 = "SMBIOSBIOSVersion:" ascii
        $key_23 = "SerialNumber:" ascii
        $key_24 = "Size:" ascii
        $key_25 = "Speed:" ascii
        $key_26 = "Version:" ascii

    condition:
        all of ($key_*)
}