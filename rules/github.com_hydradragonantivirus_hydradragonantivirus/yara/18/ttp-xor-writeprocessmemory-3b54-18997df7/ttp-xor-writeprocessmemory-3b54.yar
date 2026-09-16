rule TTP_XOR_WriteProcessMemory_3b54 {
  strings:
    $key_3b54 = { 6c 26 [2] 5e 04 [2] 58 31 [2] 76 31 [2] 49 2d }

  condition:
    any of them
}