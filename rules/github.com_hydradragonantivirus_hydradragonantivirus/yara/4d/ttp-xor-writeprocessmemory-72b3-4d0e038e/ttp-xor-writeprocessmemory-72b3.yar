rule TTP_XOR_WriteProcessMemory_72b3 {
  strings:
    $key_72b3 = { 25 c1 [2] 17 e3 [2] 11 d6 [2] 3f d6 [2] 00 ca }

  condition:
    any of them
}