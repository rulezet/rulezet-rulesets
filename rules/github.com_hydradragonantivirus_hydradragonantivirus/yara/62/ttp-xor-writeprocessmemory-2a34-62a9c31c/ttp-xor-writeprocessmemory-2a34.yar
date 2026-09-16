rule TTP_XOR_WriteProcessMemory_2a34 {
  strings:
    $key_2a34 = { 7d 46 [2] 4f 64 [2] 49 51 [2] 67 51 [2] 58 4d }

  condition:
    any of them
}