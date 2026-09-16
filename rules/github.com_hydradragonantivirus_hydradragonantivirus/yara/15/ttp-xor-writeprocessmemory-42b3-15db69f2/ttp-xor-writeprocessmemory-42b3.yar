rule TTP_XOR_WriteProcessMemory_42b3 {
  strings:
    $key_42b3 = { 15 c1 [2] 27 e3 [2] 21 d6 [2] 0f d6 [2] 30 ca }

  condition:
    any of them
}