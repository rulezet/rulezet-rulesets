rule TTP_XOR_WriteProcessMemory_25b3 {
  strings:
    $key_25b3 = { 72 c1 [2] 40 e3 [2] 46 d6 [2] 68 d6 [2] 57 ca }

  condition:
    any of them
}