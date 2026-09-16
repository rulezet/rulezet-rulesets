rule Arcane_cystack_503a7665
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_503a7665"

    strings:
        $key_0 = "BatteryStatus:" ascii
        $key_1 = "Capacity:" ascii
        $key_2 = "Caption:" ascii
        $key_3 = "ChassisTypes:" ascii
        $key_4 = "Clipboard:" ascii
        $key_5 = "Date Install:" ascii
        $key_6 = "Default:" ascii
        $key_7 = "Description:" ascii
        $key_8 = "DeviceID:" ascii
        $key_9 = "EstimatedChargeRemaining:" ascii
        $key_10 = "External IP:" ascii
        $key_11 = "FileSystem:" ascii
        $key_12 = "FreeSpace:" ascii
        $key_13 = "FullName:" ascii
        $key_14 = "Gateway IP:" ascii
        $key_15 = "HandleCount:" ascii
        $key_16 = "IPEnabled:" ascii
        $key_17 = "ISO Key:" ascii
        $key_18 = "Internal IP:" ascii
        $key_19 = "LastBootUpTime:" ascii
        $key_20 = "MACAddress:" ascii
        $key_21 = "Manufacturer:" ascii
        $key_22 = "MaxClockSpeed:" ascii
        $key_23 = "Model:" ascii
        $key_24 = "Name:" ascii
        $key_25 = "NumberOfCores:" ascii
        $key_26 = "NumberOfLogicalProcessors:" ascii
        $key_27 = "OSArchitecture:" ascii
        $key_28 = "Product:" ascii
        $key_29 = "ReleaseDate:" ascii
        $key_30 = "SMBIOSBIOSVersion:" ascii
        $key_31 = "SerialNumber:" ascii
        $key_32 = "Size:" ascii
        $key_33 = "Speed:" ascii
        $key_34 = "Version:" ascii
        $key_35 = "Worker:" ascii

    condition:
        all of ($key_*)
}