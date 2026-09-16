rule Arcane_cystack_daec173d
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_daec173d"

    strings:
        $key_0 = "AdapterRAM:" ascii
        $key_1 = "Capacity:" ascii
        $key_2 = "Caption:" ascii
        $key_3 = "ChassisTypes:" ascii
        $key_4 = "Clipboard:" ascii
        $key_5 = "Date Install:" ascii
        $key_6 = "Default:" ascii
        $key_7 = "Description:" ascii
        $key_8 = "DeviceID:" ascii
        $key_9 = "External IP:" ascii
        $key_10 = "FileSystem:" ascii
        $key_11 = "FreeSpace:" ascii
        $key_12 = "FullName:" ascii
        $key_13 = "Gateway IP:" ascii
        $key_14 = "IPEnabled:" ascii
        $key_15 = "Internal IP:" ascii
        $key_16 = "MACAddress:" ascii
        $key_17 = "Manufacturer:" ascii
        $key_18 = "MaxClockSpeed:" ascii
        $key_19 = "Model:" ascii
        $key_20 = "Name:" ascii
        $key_21 = "NumberOfCores:" ascii
        $key_22 = "OSArchitecture:" ascii
        $key_23 = "Product:" ascii
        $key_24 = "ReleaseDate:" ascii
        $key_25 = "SMBIOSBIOSVersion:" ascii
        $key_26 = "SerialNumber:" ascii
        $key_27 = "Size:" ascii
        $key_28 = "Speed:" ascii
        $key_29 = "Version:" ascii
        $key_30 = "Worker:" ascii

    condition:
        all of ($key_*)
}