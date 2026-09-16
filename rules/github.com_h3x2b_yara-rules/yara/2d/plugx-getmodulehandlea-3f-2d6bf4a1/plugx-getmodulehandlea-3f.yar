rule plugx_GetModuleHandleA_3f : APT malware
{
meta:
        author = "@h3x2b <tracker _AT h3x.eu>"
        description = "Detects obfuscated strings as used in the DLL loading the PlugX payload. String: GetModuleHandleA"

strings:
        $GetModuleHandleA_3f_00 = { 78 5a 4b 72 50 5b 4a 53 5a 77 5e 51 5b 53 5a 7e }
        $GetModuleHandleA_3f_01 = { 7a 5c 4d 74 52 5d 4c 55 5c 79 60 53 5d 55 5c 80 }
        $GetModuleHandleA_3f_02 = { 7c 5e 4f 76 54 5f 4e 57 5e 7b 62 55 5f 57 5e 02 }
        $GetModuleHandleA_3f_03 = { 7e 60 51 78 56 61 50 59 60 7d 64 57 61 59 60 04 }
        $GetModuleHandleA_3f_04 = { 80 62 53 7a 58 63 52 5b 62 7f 66 59 63 5b 62 06 }
        $GetModuleHandleA_3f_05 = { 82 64 55 7c 5a 65 54 5d 64 81 68 5b 65 5d 64 08 }
        $GetModuleHandleA_3f_06 = { 84 66 57 7e 5c 67 56 5f 66 83 6a 5d 67 5f 66 0a }
        $GetModuleHandleA_3f_07 = { 86 68 59 80 5e 69 58 61 68 85 6c 5f 69 61 68 0c }
        $GetModuleHandleA_3f_08 = { 08 6a 5b 82 60 6b 5a 63 6a 87 6e 61 6b 63 6a 0e }
        $GetModuleHandleA_3f_09 = { 0a 6c 5d 84 62 6d 5c 65 6c 09 70 63 6d 65 6c 10 }
        $GetModuleHandleA_3f_0a = { 0c 6e 5f 86 64 6f 5e 67 6e 0b 72 65 6f 67 6e 12 }
        $GetModuleHandleA_3f_0b = { 0e 70 61 88 66 71 60 69 70 0d 74 67 71 69 70 14 }
        $GetModuleHandleA_3f_0c = { 10 72 63 8a 68 73 62 6b 72 0f 76 69 73 6b 72 16 }
        $GetModuleHandleA_3f_0d = { 12 74 65 8c 6a 75 64 6d 74 11 78 6b 75 6d 74 18 }
        $GetModuleHandleA_3f_0e = { 14 76 67 0e 6c 77 66 6f 76 13 7a 6d 77 6f 76 1a }
        $GetModuleHandleA_3f_0f = { 16 78 69 10 6e 79 68 71 78 15 7c 6f 79 71 78 1c }
        $GetModuleHandleA_3f_10 = { 18 7a 6b 12 70 7b 6a 73 7a 17 7e 71 7b 73 7a 1e }
        $GetModuleHandleA_3f_11 = { 1a 7c 6d 14 72 7d 6c 75 7c 19 80 73 7d 75 7c 20 }
        $GetModuleHandleA_3f_12 = { 1c 7e 6f 16 74 7f 6e 77 7e 1b 82 75 7f 77 7e 22 }
        $GetModuleHandleA_3f_13 = { 1e 80 71 18 76 81 70 79 80 1d 84 77 81 79 80 24 }
        $GetModuleHandleA_3f_14 = { 20 82 73 1a 78 83 72 7b 82 1f 86 79 83 7b 82 26 }
        $GetModuleHandleA_3f_15 = { 22 84 75 1c 7a 85 74 7d 84 21 88 7b 85 7d 84 28 }
        $GetModuleHandleA_3f_16 = { 24 86 77 1e 7c 87 76 7f 86 23 8a 7d 87 7f 86 2a }
        $GetModuleHandleA_3f_17 = { 26 88 79 20 7e 89 78 81 88 25 8c 7f 89 81 88 2c }
        $GetModuleHandleA_3f_18 = { 28 8a 7b 22 80 8b 7a 83 8a 27 8e 81 8b 83 8a 2e }
        $GetModuleHandleA_3f_19 = { 2a 8c 7d 24 82 8d 7c 85 8c 29 90 83 8d 85 8c 30 }
        $GetModuleHandleA_3f_1a = { 2c 8e 7f 26 84 8f 7e 87 8e 2b 92 85 8f 87 8e 32 }
        $GetModuleHandleA_3f_1b = { 2e 90 81 28 86 91 80 89 90 2d 94 87 91 89 90 34 }
        $GetModuleHandleA_3f_1c = { 30 92 83 2a 88 93 82 8b 92 2f 96 89 93 8b 92 36 }
        $GetModuleHandleA_3f_1d = { 32 94 85 2c 8a 95 84 8d 94 31 98 8b 95 8d 94 38 }
        $GetModuleHandleA_3f_1e = { 34 96 87 2e 8c 97 86 8f 96 33 9a 8d 97 8f 96 3a }
        $GetModuleHandleA_3f_1f = { 36 98 89 30 8e 99 88 91 98 35 9c 8f 99 91 98 3c }
        $GetModuleHandleA_3f_20 = { 38 9a 8b 32 90 9b 8a 93 9a 37 9e 91 9b 93 9a 3e }
        $GetModuleHandleA_3f_21 = { 3a 9c 8d 34 92 9d 8c 95 9c 39 a0 93 9d 95 9c 40 }
        $GetModuleHandleA_3f_22 = { 3c 9e 8f 36 94 9f 8e 97 9e 3b 22 95 9f 97 9e 42 }
        $GetModuleHandleA_3f_23 = { 3e a0 91 38 96 a1 90 99 a0 3d 24 97 a1 99 a0 44 }
        $GetModuleHandleA_3f_24 = { 40 a2 93 3a 98 a3 92 9b a2 3f 26 99 a3 9b a2 46 }
        $GetModuleHandleA_3f_25 = { 42 a4 95 3c 9a 25 94 9d a4 41 28 9b 25 9d a4 48 }
        $GetModuleHandleA_3f_26 = { 44 26 97 3e 9c 27 96 9f 26 43 2a 9d 27 9f 26 4a }
        $GetModuleHandleA_3f_27 = { 46 28 99 40 9e 29 98 a1 28 45 2c 9f 29 a1 28 4c }
        $GetModuleHandleA_3f_28 = { 48 2a 9b 42 a0 2b 9a a3 2a 47 2e a1 2b a3 2a 4e }
        $GetModuleHandleA_3f_29 = { 4a 2c 9d 44 a2 2d 9c a5 2c 49 30 a3 2d a5 2c 50 }
        $GetModuleHandleA_3f_2a = { 4c 2e 9f 46 a4 2f 9e a7 2e 4b 32 a5 2f a7 2e 52 }
        $GetModuleHandleA_3f_2b = { 4e 30 a1 48 a6 31 a0 a9 30 4d 34 a7 31 a9 30 54 }
        $GetModuleHandleA_3f_2c = { 50 32 a3 4a a8 33 a2 ab 32 4f 36 a9 33 ab 32 56 }
        $GetModuleHandleA_3f_2d = { 52 34 a5 4c aa 35 a4 2d 34 51 38 ab 35 2d 34 58 }
        $GetModuleHandleA_3f_2e = { 54 36 a7 4e ac 37 a6 2f 36 53 3a ad 37 2f 36 5a }
        $GetModuleHandleA_3f_2f = { 56 38 a9 50 ae 39 a8 31 38 55 3c 2f 39 31 38 5c }
        $GetModuleHandleA_3f_30 = { 58 3a ab 52 30 3b aa 33 3a 57 3e 31 3b 33 3a 5e }
        $GetModuleHandleA_3f_31 = { 5a 3c ad 54 32 3d ac 35 3c 59 40 33 3d 35 3c 60 }
        $GetModuleHandleA_3f_32 = { 5c 3e af 56 34 3f ae 37 3e 5b 42 35 3f 37 3e 62 }
        $GetModuleHandleA_3f_33 = { 5e 40 b1 58 36 41 b0 39 40 5d 44 37 41 39 40 64 }
        $GetModuleHandleA_3f_34 = { 60 42 b3 5a 38 43 b2 3b 42 5f 46 39 43 3b 42 66 }
        $GetModuleHandleA_3f_35 = { 62 44 35 5c 3a 45 b4 3d 44 61 48 3b 45 3d 44 68 }
        $GetModuleHandleA_3f_36 = { 64 46 37 5e 3c 47 36 3f 46 63 4a 3d 47 3f 46 6a }
        $GetModuleHandleA_3f_37 = { 66 48 39 60 3e 49 38 41 48 65 4c 3f 49 41 48 6c }
        $GetModuleHandleA_3f_38 = { 68 4a 3b 62 40 4b 3a 43 4a 67 4e 41 4b 43 4a 6e }
        $GetModuleHandleA_3f_39 = { 6a 4c 3d 64 42 4d 3c 45 4c 69 50 43 4d 45 4c 70 }
        $GetModuleHandleA_3f_3a = { 6c 4e 3f 66 44 4f 3e 47 4e 6b 52 45 4f 47 4e 72 }
        $GetModuleHandleA_3f_3b = { 6e 50 41 68 46 51 40 49 50 6d 54 47 51 49 50 74 }
        $GetModuleHandleA_3f_3c = { 70 52 43 6a 48 53 42 4b 52 6f 56 49 53 4b 52 76 }
        $GetModuleHandleA_3f_3d = { 72 54 45 6c 4a 55 44 4d 54 71 58 4b 55 4d 54 78 }
        $GetModuleHandleA_3f_3e = { 74 56 47 6e 4c 57 46 4f 56 73 5a 4d 57 4f 56 7a }
        $GetModuleHandleA_3f_3f = { 76 58 49 70 4e 59 48 51 58 75 5c 4f 59 51 58 7c }

    condition:
                uint16(0) == 0x5a4d and
        1 of them
}