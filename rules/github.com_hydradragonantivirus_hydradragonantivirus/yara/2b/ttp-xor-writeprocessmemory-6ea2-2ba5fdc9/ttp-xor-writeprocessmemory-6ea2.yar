rule TTP_XOR_WriteProcessMemory_6ea2 {
  strings:
    $key_6ea2 = { 39 d0 [2] 0b f2 [2] 0d c7 [2] 23 c7 [2] 1c db }

  condition:
    any of them
}