rule TTP_XOR_WriteProcessMemory_c743 {
  strings:
    $key_c743 = { 90 31 [2] a2 13 [2] a4 26 [2] 8a 26 [2] b5 3a }

  condition:
    any of them
}