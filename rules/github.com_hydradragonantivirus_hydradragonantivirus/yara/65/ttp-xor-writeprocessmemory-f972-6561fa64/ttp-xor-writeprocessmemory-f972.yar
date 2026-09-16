rule TTP_XOR_WriteProcessMemory_f972 {
  strings:
    $key_f972 = { ae 00 [2] 9c 22 [2] 9a 17 [2] b4 17 [2] 8b 0b }

  condition:
    any of them
}