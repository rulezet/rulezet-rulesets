rule TTP_XOR_WriteProcessMemory_52b3 {
  strings:
    $key_52b3 = { 05 c1 [2] 37 e3 [2] 31 d6 [2] 1f d6 [2] 20 ca }

  condition:
    any of them
}