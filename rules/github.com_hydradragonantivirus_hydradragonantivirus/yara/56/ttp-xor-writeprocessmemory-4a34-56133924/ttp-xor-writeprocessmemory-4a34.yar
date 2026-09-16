rule TTP_XOR_WriteProcessMemory_4a34 {
  strings:
    $key_4a34 = { 1d 46 [2] 2f 64 [2] 29 51 [2] 07 51 [2] 38 4d }

  condition:
    any of them
}