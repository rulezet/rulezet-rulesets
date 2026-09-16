rule TTP_XOR_WriteProcessMemory_6bb3 {
  strings:
    $key_6bb3 = { 3c c1 [2] 0e e3 [2] 08 d6 [2] 26 d6 [2] 19 ca }

  condition:
    any of them
}