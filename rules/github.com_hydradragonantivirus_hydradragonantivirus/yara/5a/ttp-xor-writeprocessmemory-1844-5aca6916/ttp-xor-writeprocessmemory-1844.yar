rule TTP_XOR_WriteProcessMemory_1844 {
  strings:
    $key_1844 = { 4f 36 [2] 7d 14 [2] 7b 21 [2] 55 21 [2] 6a 3d }

  condition:
    any of them
}