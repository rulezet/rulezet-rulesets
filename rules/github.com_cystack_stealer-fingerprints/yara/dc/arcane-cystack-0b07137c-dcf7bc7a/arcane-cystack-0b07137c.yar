rule Arcane_cystack_0b07137c
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_0b07137c"

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
        $key_16 = "IPEnabled:" ascii
        $key_17 = "ISO Key:" ascii
        $key_18 = "Internal IP:" ascii
        $key_19 = "MACAddress:" ascii
        $key_20 = "Manufacturer:" ascii
        $key_21 = "MaxClockSpeed:" ascii
        $key_22 = "Model:" ascii
        $key_23 = "Name:" ascii
        $key_24 = "NumberOfCores:" ascii
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