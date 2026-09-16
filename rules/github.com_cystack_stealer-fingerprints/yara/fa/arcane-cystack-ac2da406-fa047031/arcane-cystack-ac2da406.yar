rule Arcane_cystack_ac2da406
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_ac2da406"

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
        $key_14 = "HandleCount:" ascii
        $key_15 = "IPEnabled:" ascii
        $key_16 = "ISO Key:" ascii
        $key_17 = "Internal IP:" ascii
        $key_18 = "LastBootUpTime:" ascii
        $key_19 = "MACAddress:" ascii
        $key_20 = "Manufacturer:" ascii
        $key_21 = "MaxClockSpeed:" ascii
        $key_22 = "Model:" ascii
        $key_23 = "Name:" ascii
        $key_24 = "NumberOfCores:" ascii
        $key_25 = "NumberOfLogicalProcessors:" ascii
        $key_26 = "OSArchitecture:" ascii
        $key_27 = "Product:" ascii
        $key_28 = "ReleaseDate:" ascii
        $key_29 = "SMBIOSBIOSVersion:" ascii
        $key_30 = "SerialNumber:" ascii
        $key_31 = "Size:" ascii
        $key_32 = "Speed:" ascii
        $key_33 = "Version:" ascii
        $key_34 = "Worker:" ascii

    condition:
        all of ($key_*)
}