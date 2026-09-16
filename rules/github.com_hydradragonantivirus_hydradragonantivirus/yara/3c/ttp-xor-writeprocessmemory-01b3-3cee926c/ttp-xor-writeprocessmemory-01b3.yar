rule TTP_XOR_WriteProcessMemory_01b3 {
  strings:
    $key_01b3 = { 56 c1 [2] 64 e3 [2] 62 d6 [2] 4c d6 [2] 73 ca }

  condition:
    any of them
}