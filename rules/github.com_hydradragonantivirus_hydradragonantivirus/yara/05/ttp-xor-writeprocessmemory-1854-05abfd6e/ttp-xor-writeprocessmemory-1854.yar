rule TTP_XOR_WriteProcessMemory_1854 {
  strings:
    $key_1854 = { 4f 26 [2] 7d 04 [2] 7b 31 [2] 55 31 [2] 6a 2d }

  condition:
    any of them
}