rule TTP_XOR_WriteProcessMemory_4ab3 {
  strings:
    $key_4ab3 = { 1d c1 [2] 2f e3 [2] 29 d6 [2] 07 d6 [2] 38 ca }

  condition:
    any of them
}