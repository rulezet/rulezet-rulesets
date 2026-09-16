rule TTP_XOR_WriteProcessMemory_0bb3 {
  strings:
    $key_0bb3 = { 5c c1 [2] 6e e3 [2] 68 d6 [2] 46 d6 [2] 79 ca }

  condition:
    any of them
}