rule TTP_XOR_WriteProcessMemory_1334 {
  strings:
    $key_1334 = { 44 46 [2] 76 64 [2] 70 51 [2] 5e 51 [2] 61 4d }

  condition:
    any of them
}