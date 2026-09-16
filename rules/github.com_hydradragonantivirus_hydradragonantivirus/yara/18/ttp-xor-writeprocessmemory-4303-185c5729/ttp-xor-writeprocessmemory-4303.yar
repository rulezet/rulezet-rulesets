rule TTP_XOR_WriteProcessMemory_4303 {
  strings:
    $key_4303 = { 14 71 [2] 26 53 [2] 20 66 [2] 0e 66 [2] 31 7a }

  condition:
    any of them
}