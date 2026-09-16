rule TTP_XOR_WriteProcessMemory_44b3 {
  strings:
    $key_44b3 = { 13 c1 [2] 21 e3 [2] 27 d6 [2] 09 d6 [2] 36 ca }

  condition:
    any of them
}