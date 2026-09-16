rule TTP_XOR_WriteProcessMemory_4ea2 {
  strings:
    $key_4ea2 = { 19 d0 [2] 2b f2 [2] 2d c7 [2] 03 c7 [2] 3c db }

  condition:
    any of them
}