rule plugx_advapi32_dll_3f : APT malware
{
    meta:
        author = "@h3x2b <tracker _AT h3x.eu>"
        description = "Detects obfuscated strings as used in the DLL loading the PlugX payload. String: advapi32.dll"
    strings:
        $advapi32_dll_3f_00 = { 5e 5b 49 5e 4f 56 0c 0d 11 5b 53 53 }
        $advapi32_dll_3f_01 = { 60 5d 4b 60 51 58 0e 0f 13 5d 55 55 }
        $advapi32_dll_3f_02 = { 62 5f 4d 62 53 5a 10 11 15 5f 57 57 }
        $advapi32_dll_3f_03 = { 64 61 4f 64 55 5c 12 13 17 61 59 59 }
        $advapi32_dll_3f_04 = { 66 63 51 66 57 5e 14 15 19 63 5b 5b }
        $advapi32_dll_3f_05 = { 68 65 53 68 59 60 16 17 1b 65 5d 5d }
        $advapi32_dll_3f_06 = { 6a 67 55 6a 5b 62 18 19 1d 67 5f 5f }
        $advapi32_dll_3f_07 = { 6c 69 57 6c 5d 64 1a 1b 1f 69 61 61 }
        $advapi32_dll_3f_08 = { 6e 6b 59 6e 5f 66 1c 1d 21 6b 63 63 }
        $advapi32_dll_3f_09 = { 70 6d 5b 70 61 68 1e 1f 23 6d 65 65 }
        $advapi32_dll_3f_0a = { 72 6f 5d 72 63 6a 20 21 25 6f 67 67 }
        $advapi32_dll_3f_0b = { 74 71 5f 74 65 6c 22 23 27 71 69 69 }
        $advapi32_dll_3f_0c = { 76 73 61 76 67 6e 24 25 29 73 6b 6b }
        $advapi32_dll_3f_0d = { 78 75 63 78 69 70 26 27 2b 75 6d 6d }
        $advapi32_dll_3f_0e = { 7a 77 65 7a 6b 72 28 29 2d 77 6f 6f }
        $advapi32_dll_3f_0f = { 7c 79 67 7c 6d 74 2a 2b 2f 79 71 71 }
        $advapi32_dll_3f_10 = { 7e 7b 69 7e 6f 76 2c 2d 31 7b 73 73 }
        $advapi32_dll_3f_11 = { 80 7d 6b 80 71 78 2e 2f 33 7d 75 75 }
        $advapi32_dll_3f_12 = { 82 7f 6d 82 73 7a 30 31 35 7f 77 77 }
        $advapi32_dll_3f_13 = { 84 81 6f 84 75 7c 32 33 37 81 79 79 }
        $advapi32_dll_3f_14 = { 86 83 71 86 77 7e 34 35 39 83 7b 7b }
        $advapi32_dll_3f_15 = { 88 85 73 88 79 80 36 37 3b 85 7d 7d }
        $advapi32_dll_3f_16 = { 8a 87 75 8a 7b 82 38 39 3d 87 7f 7f }
        $advapi32_dll_3f_17 = { 8c 89 77 8c 7d 84 3a 3b 3f 89 81 81 }
        $advapi32_dll_3f_18 = { 8e 8b 79 8e 7f 86 3c 3d 41 8b 83 83 }
        $advapi32_dll_3f_19 = { 90 8d 7b 90 81 88 3e 3f 43 8d 85 85 }
        $advapi32_dll_3f_1a = { 92 8f 7d 92 83 8a 40 41 45 8f 87 87 }
        $advapi32_dll_3f_1b = { 94 91 7f 94 85 8c 42 43 47 91 89 89 }
        $advapi32_dll_3f_1c = { 96 93 81 96 87 8e 44 45 49 93 8b 8b }
        $advapi32_dll_3f_1d = { 98 95 83 98 89 90 46 47 4b 95 8d 8d }
        $advapi32_dll_3f_1e = { 9a 97 85 9a 8b 92 48 49 4d 97 8f 8f }
        $advapi32_dll_3f_1f = { 9c 99 87 9c 8d 94 4a 4b 4f 99 91 91 }
        $advapi32_dll_3f_20 = { 9e 9b 89 9e 8f 96 4c 4d 51 9b 93 93 }
        $advapi32_dll_3f_21 = { a0 9d 8b a0 91 98 4e 4f 53 9d 95 95 }
        $advapi32_dll_3f_22 = { 22 9f 8d 22 93 9a 50 51 55 9f 97 97 }
        $advapi32_dll_3f_23 = { 24 a1 8f 24 95 9c 52 53 57 a1 99 99 }
        $advapi32_dll_3f_24 = { 26 a3 91 26 97 9e 54 55 59 a3 9b 9b }
        $advapi32_dll_3f_25 = { 28 25 93 28 99 a0 56 57 5b 25 9d 9d }
        $advapi32_dll_3f_26 = { 2a 27 95 2a 9b a2 58 59 5d 27 9f 9f }
        $advapi32_dll_3f_27 = { 2c 29 97 2c 9d a4 5a 5b 5f 29 a1 a1 }
        $advapi32_dll_3f_28 = { 2e 2b 99 2e 9f a6 5c 5d 61 2b a3 a3 }
        $advapi32_dll_3f_29 = { 30 2d 9b 30 a1 a8 5e 5f 63 2d a5 a5 }
        $advapi32_dll_3f_2a = { 32 2f 9d 32 a3 2a 60 61 65 2f a7 a7 }
        $advapi32_dll_3f_2b = { 34 31 9f 34 a5 2c 62 63 67 31 a9 a9 }
        $advapi32_dll_3f_2c = { 36 33 a1 36 a7 2e 64 65 69 33 ab ab }
        $advapi32_dll_3f_2d = { 38 35 a3 38 a9 30 66 67 6b 35 2d 2d }
        $advapi32_dll_3f_2e = { 3a 37 a5 3a ab 32 68 69 6d 37 2f 2f }
        $advapi32_dll_3f_2f = { 3c 39 a7 3c ad 34 6a 6b ef 39 31 31 }
        $advapi32_dll_3f_30 = { 3e 3b a9 3e af 36 6c 6d f1 3b 33 33 }
        $advapi32_dll_3f_31 = { 40 3d ab 40 31 38 6e 6f f3 3d 35 35 }
        $advapi32_dll_3f_32 = { 42 3f ad 42 33 3a 70 71 f5 3f 37 37 }
        $advapi32_dll_3f_33 = { 44 41 af 44 35 3c 72 f3 f7 41 39 39 }
        $advapi32_dll_3f_34 = { 46 43 b1 46 37 3e f4 f5 f9 43 3b 3b }
        $advapi32_dll_3f_35 = { 48 45 b3 48 39 40 f6 f7 fb 45 3d 3d }
        $advapi32_dll_3f_36 = { 4a 47 b5 4a 3b 42 f8 f9 fd 47 3f 3f }
        $advapi32_dll_3f_37 = { 4c 49 37 4c 3d 44 fa fb ff 49 41 41 }
        $advapi32_dll_3f_38 = { 4e 4b 39 4e 3f 46 fc fd 01 4b 43 43 }
        $advapi32_dll_3f_39 = { 50 4d 3b 50 41 48 fe ff 03 4d 45 45 }
        $advapi32_dll_3f_3a = { 52 4f 3d 52 43 4a 00 01 05 4f 47 47 }
        $advapi32_dll_3f_3b = { 54 51 3f 54 45 4c 02 03 07 51 49 49 }
        $advapi32_dll_3f_3c = { 56 53 41 56 47 4e 04 05 09 53 4b 4b }
        $advapi32_dll_3f_3d = { 58 55 43 58 49 50 06 07 0b 55 4d 4d }
        $advapi32_dll_3f_3e = { 5a 57 45 5a 4b 52 08 09 0d 57 4f 4f }
        $advapi32_dll_3f_3f = { 5c 59 47 5c 4d 54 0a 0b 0f 59 51 51 }

    condition:
                uint16(0) == 0x5a4d and
        1 of them
}