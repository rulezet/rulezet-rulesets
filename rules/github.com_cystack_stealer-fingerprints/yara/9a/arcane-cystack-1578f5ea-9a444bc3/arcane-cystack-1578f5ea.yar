rule Arcane_cystack_1578f5ea
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_1578f5ea"

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
        $key_12 = "Gateway IP:" ascii
        $key_13 = "HandleCount:" ascii
        $key_14 = "IPEnabled:" ascii
        $key_15 = "ISO Key:" ascii
        $key_16 = "Internal IP:" ascii
        $key_17 = "LastBootUpTime:" ascii
        $key_18 = "MACAddress:" ascii
        $key_19 = "Manufacturer:" ascii
        $key_20 = "MaxClockSpeed:" ascii
        $key_21 = "Model:" ascii
        $key_22 = "Name:" ascii
        $key_23 = "NumberOfCores:" ascii
        $key_24 = "NumberOfLogicalProcessors:" ascii
        $key_25 = "OSArchitecture:" ascii
        $key_26 = "Product:" ascii
        $key_27 = "ReleaseDate:" ascii
        $key_28 = "SMBIOSBIOSVersion:" ascii
        $key_29 = "SerialNumber:" ascii
        $key_30 = "Size:" ascii
        $key_31 = "Speed:" ascii
        $key_32 = "Version:" ascii
        $key_33 = "Worker:" ascii

    condition:
        all of ($key_*)
}