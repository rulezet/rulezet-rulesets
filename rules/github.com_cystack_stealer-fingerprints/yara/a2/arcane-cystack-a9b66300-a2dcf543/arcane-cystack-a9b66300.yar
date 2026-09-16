rule Arcane_cystack_a9b66300
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_a9b66300"

    strings:
        $key_0 = "AdapterRAM:" ascii
        $key_1 = "BatteryStatus:" ascii
        $key_2 = "Capacity:" ascii
        $key_3 = "Caption:" ascii
        $key_4 = "ChassisTypes:" ascii
        $key_5 = "Clipboard:" ascii
        $key_6 = "Date Install:" ascii
        $key_7 = "Default:" ascii
        $key_8 = "Description:" ascii
        $key_9 = "DeviceID:" ascii
        $key_10 = "EstimatedChargeRemaining:" ascii
        $key_11 = "External IP:" ascii
        $key_12 = "FileSystem:" ascii
        $key_13 = "FreeSpace:" ascii
        $key_14 = "FullName:" ascii
        $key_15 = "Gateway IP:" ascii
        $key_16 = "HandleCount:" ascii
        $key_17 = "IPEnabled:" ascii
        $key_18 = "ISO Key:" ascii
        $key_19 = "Internal IP:" ascii
        $key_20 = "LastBootUpTime:" ascii
        $key_21 = "MACAddress:" ascii
        $key_22 = "Manufacturer:" ascii
        $key_23 = "MaxClockSpeed:" ascii
        $key_24 = "Model:" ascii
        $key_25 = "Name:" ascii
        $key_26 = "NumberOfCores:" ascii
        $key_27 = "NumberOfLogicalProcessors:" ascii
        $key_28 = "OSArchitecture:" ascii
        $key_29 = "Product:" ascii
        $key_30 = "ReleaseDate:" ascii
        $key_31 = "SMBIOSBIOSVersion:" ascii
        $key_32 = "SerialNumber:" ascii
        $key_33 = "Size:" ascii
        $key_34 = "Speed:" ascii
        $key_35 = "Version:" ascii
        $key_36 = "Worker:" ascii

    condition:
        all of ($key_*)
}