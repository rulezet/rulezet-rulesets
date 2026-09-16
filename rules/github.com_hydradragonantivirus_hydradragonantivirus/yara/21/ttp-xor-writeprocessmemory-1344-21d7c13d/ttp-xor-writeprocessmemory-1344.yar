rule TTP_XOR_WriteProcessMemory_1344 {
  strings:
    $key_1344 = { 44 36 [2] 76 14 [2] 70 21 [2] 5e 21 [2] 61 3d }

  condition:
    any of them
}