rule TTP_XOR_WriteProcessMemory_12b3 {
  strings:
    $key_12b3 = { 45 c1 [2] 77 e3 [2] 71 d6 [2] 5f d6 [2] 60 ca }

  condition:
    any of them
}