rule TTP_XOR_WriteProcessMemory_40b3 {
  strings:
    $key_40b3 = { 17 c1 [2] 25 e3 [2] 23 d6 [2] 0d d6 [2] 32 ca }

  condition:
    any of them
}