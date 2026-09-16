rule TTP_XOR_WriteProcessMemory_4801 {
  strings:
    $key_4801 = { 1f 73 [2] 2d 51 [2] 2b 64 [2] 05 64 [2] 3a 78 }

  condition:
    any of them
}