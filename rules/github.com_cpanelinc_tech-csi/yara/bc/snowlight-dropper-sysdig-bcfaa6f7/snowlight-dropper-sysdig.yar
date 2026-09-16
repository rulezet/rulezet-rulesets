rule SNOWLIGHT_DROPPER_SYSDIG {
        meta:
                author = "Alessandra Rizzo"
                description = "This rule detects strings seen in SNOWLIGHT malware acting as a dropper for fileless payloads."
                md5 = "96f307b0ba3bb11715fab5db8d61191f"
                platforms = "Linux"
                malware_family = "SNOWLIGHT"
        strings:
                $http_get_request = { 77 73 5f 00 6c 36 34 00 47 45 54 20 2f 3f 61 3d 25 73 26 68 3d 25 73 26 74 3d 25 73 26 70 3d 25 64 }
                $user_agent = { 55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 72 76 3a 34 38 2e 30 29 20 47 65 63 6b 6f 2f 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6f 78 2f 34 38 2e 30 }
  $fileless_payload_masked_name = { 5b 6b 77 6f 72 6b 65 72 2f 30 3a 32 }
        condition:
                uint32(0) == 0x464c457f and all of them
}