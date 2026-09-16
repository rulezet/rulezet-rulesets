rule plugx_VirtualProtect_3f : APT malware
{
    meta:
        author = "@h3x2b <tracker _AT h3x.eu>"
        description = "Detects obfuscated strings as used in the DLL loading the PlugX payload. String: VirtualProtect"
    strings:
        $VirtualProtect_3f_00 = { 69 56 4d 4b 4a 5e 53 6f 4d 50 4b 5a 5c 4b }
        $VirtualProtect_3f_01 = { 6b 58 4f 4d 4c 60 55 71 4f 52 4d 5c 5e 4d }
        $VirtualProtect_3f_02 = { 6d 5a 51 4f 4e 62 57 73 51 54 4f 5e 60 4f }
        $VirtualProtect_3f_03 = { 6f 5c 53 51 50 64 59 75 53 56 51 60 62 51 }
        $VirtualProtect_3f_04 = { 71 5e 55 53 52 66 5b 77 55 58 53 62 64 53 }
        $VirtualProtect_3f_05 = { 73 60 57 55 54 68 5d 79 57 5a 55 64 66 55 }
        $VirtualProtect_3f_06 = { 75 62 59 57 56 6a 5f 7b 59 5c 57 66 68 57 }
        $VirtualProtect_3f_07 = { 77 64 5b 59 58 6c 61 7d 5b 5e 59 68 6a 59 }
        $VirtualProtect_3f_08 = { 79 66 5d 5b 5a 6e 63 7f 5d 60 5b 6a 6c 5b }
        $VirtualProtect_3f_09 = { 7b 68 5f 5d 5c 70 65 81 5f 62 5d 6c 6e 5d }
        $VirtualProtect_3f_0a = { 7d 6a 61 5f 5e 72 67 83 61 64 5f 6e 70 5f }
        $VirtualProtect_3f_0b = { 7f 6c 63 61 60 74 69 85 63 66 61 70 72 61 }
        $VirtualProtect_3f_0c = { 81 6e 65 63 62 76 6b 87 65 68 63 72 74 63 }
        $VirtualProtect_3f_0d = { 83 70 67 65 64 78 6d 89 67 6a 65 74 76 65 }
        $VirtualProtect_3f_0e = { 85 72 69 67 66 7a 6f 8b 69 6c 67 76 78 67 }
        $VirtualProtect_3f_0f = { 87 74 6b 69 68 7c 71 8d 6b 6e 69 78 7a 69 }
        $VirtualProtect_3f_10 = { 89 76 6d 6b 6a 7e 73 8f 6d 70 6b 7a 7c 6b }
        $VirtualProtect_3f_11 = { 8b 78 6f 6d 6c 80 75 11 6f 72 6d 7c 7e 6d }
        $VirtualProtect_3f_12 = { 8d 7a 71 6f 6e 82 77 13 71 74 6f 7e 80 6f }
        $VirtualProtect_3f_13 = { 8f 7c 73 71 70 84 79 15 73 76 71 80 82 71 }
        $VirtualProtect_3f_14 = { 91 7e 75 73 72 86 7b 17 75 78 73 82 84 73 }
        $VirtualProtect_3f_15 = { 93 80 77 75 74 88 7d 19 77 7a 75 84 86 75 }
        $VirtualProtect_3f_16 = { 95 82 79 77 76 8a 7f 1b 79 7c 77 86 88 77 }
        $VirtualProtect_3f_17 = { 17 84 7b 79 78 8c 81 1d 7b 7e 79 88 8a 79 }
        $VirtualProtect_3f_18 = { 19 86 7d 7b 7a 8e 83 1f 7d 80 7b 8a 8c 7b }
        $VirtualProtect_3f_19 = { 1b 88 7f 7d 7c 90 85 21 7f 82 7d 8c 8e 7d }
        $VirtualProtect_3f_1a = { 1d 8a 81 7f 7e 92 87 23 81 84 7f 8e 90 7f }
        $VirtualProtect_3f_1b = { 1f 8c 83 81 80 94 89 25 83 86 81 90 92 81 }
        $VirtualProtect_3f_1c = { 21 8e 85 83 82 96 8b 27 85 88 83 92 94 83 }
        $VirtualProtect_3f_1d = { 23 90 87 85 84 98 8d 29 87 8a 85 94 96 85 }
        $VirtualProtect_3f_1e = { 25 92 89 87 86 9a 8f 2b 89 8c 87 96 98 87 }
        $VirtualProtect_3f_1f = { 27 94 8b 89 88 9c 91 2d 8b 8e 89 98 9a 89 }
        $VirtualProtect_3f_20 = { 29 96 8d 8b 8a 9e 93 2f 8d 90 8b 9a 9c 8b }
        $VirtualProtect_3f_21 = { 2b 98 8f 8d 8c a0 95 31 8f 92 8d 9c 9e 8d }
        $VirtualProtect_3f_22 = { 2d 9a 91 8f 8e 22 97 33 91 94 8f 9e a0 8f }
        $VirtualProtect_3f_23 = { 2f 9c 93 91 90 24 99 35 93 96 91 a0 a2 91 }
        $VirtualProtect_3f_24 = { 31 9e 95 93 92 26 9b 37 95 98 93 a2 24 93 }
        $VirtualProtect_3f_25 = { 33 a0 97 95 94 28 9d 39 97 9a 95 a4 26 95 }
        $VirtualProtect_3f_26 = { 35 a2 99 97 96 2a 9f 3b 99 9c 97 26 28 97 }
        $VirtualProtect_3f_27 = { 37 a4 9b 99 98 2c a1 3d 9b 9e 99 28 2a 99 }
        $VirtualProtect_3f_28 = { 39 a6 9d 9b 9a 2e a3 3f 9d a0 9b 2a 2c 9b }
        $VirtualProtect_3f_29 = { 3b a8 9f 9d 9c 30 a5 41 9f a2 9d 2c 2e 9d }
        $VirtualProtect_3f_2a = { 3d 2a a1 9f 9e 32 a7 43 a1 a4 9f 2e 30 9f }
        $VirtualProtect_3f_2b = { 3f 2c a3 a1 a0 34 a9 45 a3 a6 a1 30 32 a1 }
        $VirtualProtect_3f_2c = { 41 2e a5 a3 a2 36 ab 47 a5 a8 a3 32 34 a3 }
        $VirtualProtect_3f_2d = { 43 30 a7 a5 a4 38 2d 49 a7 aa a5 34 36 a5 }
        $VirtualProtect_3f_2e = { 45 32 a9 a7 a6 3a 2f 4b a9 ac a7 36 38 a7 }
        $VirtualProtect_3f_2f = { 47 34 ab a9 a8 3c 31 4d ab ae a9 38 3a a9 }
        $VirtualProtect_3f_30 = { 49 36 ad ab aa 3e 33 4f ad 30 ab 3a 3c ab }
        $VirtualProtect_3f_31 = { 4b 38 af ad ac 40 35 51 af 32 ad 3c 3e ad }
        $VirtualProtect_3f_32 = { 4d 3a b1 af ae 42 37 53 b1 34 af 3e 40 af }
        $VirtualProtect_3f_33 = { 4f 3c 33 b1 b0 44 39 55 33 36 b1 40 42 b1 }
        $VirtualProtect_3f_34 = { 51 3e 35 b3 b2 46 3b 57 35 38 b3 42 44 b3 }
        $VirtualProtect_3f_35 = { 53 40 37 35 b4 48 3d 59 37 3a 35 44 46 35 }
        $VirtualProtect_3f_36 = { 55 42 39 37 36 4a 3f 5b 39 3c 37 46 48 37 }
        $VirtualProtect_3f_37 = { 57 44 3b 39 38 4c 41 5d 3b 3e 39 48 4a 39 }
        $VirtualProtect_3f_38 = { 59 46 3d 3b 3a 4e 43 5f 3d 40 3b 4a 4c 3b }
        $VirtualProtect_3f_39 = { 5b 48 3f 3d 3c 50 45 61 3f 42 3d 4c 4e 3d }
        $VirtualProtect_3f_3a = { 5d 4a 41 3f 3e 52 47 63 41 44 3f 4e 50 3f }
        $VirtualProtect_3f_3b = { 5f 4c 43 41 40 54 49 65 43 46 41 50 52 41 }
        $VirtualProtect_3f_3c = { 61 4e 45 43 42 56 4b 67 45 48 43 52 54 43 }
        $VirtualProtect_3f_3d = { 63 50 47 45 44 58 4d 69 47 4a 45 54 56 45 }
        $VirtualProtect_3f_3e = { 65 52 49 47 46 5a 4f 6b 49 4c 47 56 58 47 }
        $VirtualProtect_3f_3f = { 67 54 4b 49 48 5c 51 6d 4b 4e 49 58 5a 49 }

    condition:
                uint16(0) == 0x5a4d and
        1 of them
}