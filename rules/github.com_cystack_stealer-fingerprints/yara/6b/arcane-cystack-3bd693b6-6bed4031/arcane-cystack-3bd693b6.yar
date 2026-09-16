rule Arcane_cystack_3bd693b6
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_3bd693b6"

    strings:
        $key_0 = "AdapterRAM:" ascii
        $key_1 = "Capacity:" ascii
        $key_2 = "Caption:" ascii
        $key_3 = "ChassisTypes:" ascii
        $key_4 = "Date Install:" ascii
        $key_5 = "Default:" ascii
        $key_6 = "Description:" ascii
        $key_7 = "DeviceID:" ascii
        $key_8 = "FileSystem:" ascii
        $key_9 = "FreeSpace:" ascii
        $key_10 = "FullName:" ascii
        $key_11 = "IPEnabled:" ascii
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
        $key_26 = "Worker:" ascii

    condition:
        all of ($key_*)
}