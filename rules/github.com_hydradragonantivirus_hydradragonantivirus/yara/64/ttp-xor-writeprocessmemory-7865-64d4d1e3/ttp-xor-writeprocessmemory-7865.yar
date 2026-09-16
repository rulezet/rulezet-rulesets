rule TTP_XOR_WriteProcessMemory_7865 {
  strings:
    $key_7865 = { 2f 17 [2] 1d 35 [2] 1b 00 [2] 35 00 [2] 0a 1c }

  condition:
    any of them
}