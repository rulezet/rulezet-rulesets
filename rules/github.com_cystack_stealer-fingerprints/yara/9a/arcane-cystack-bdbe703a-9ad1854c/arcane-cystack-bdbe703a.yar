rule Arcane_cystack_bdbe703a
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_bdbe703a"

    strings:
        $key_0 = "AdapterRAM:" ascii
        $key_1 = "Annex 2a:" ascii
        $key_2 = "BatteryStatus:" ascii
        $key_3 = "Capacity:" ascii
        $key_4 = "Caption:" ascii
        $key_5 = "ChassisTypes:" ascii
        $key_6 = "Clipboard:" ascii
        $key_7 = "Date Install:" ascii
        $key_8 = "Default:" ascii
        $key_9 = "Description:" ascii
        $key_10 = "DeviceID:" ascii
        $key_11 = "EstimatedChargeRemaining:" ascii
        $key_12 = "External IP:" ascii
        $key_13 = "FileSystem:" ascii
        $key_14 = "FreeSpace:" ascii
        $key_15 = "FullName:" ascii
        $key_16 = "Gateway IP:" ascii
        $key_17 = "IPEnabled:" ascii
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