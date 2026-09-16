rule TTP_XOR_WriteProcessMemory_4891 {
  strings:
    $key_4891 = { 1f e3 [2] 2d c1 [2] 2b f4 [2] 05 f4 [2] 3a e8 }

  condition:
    any of them
}