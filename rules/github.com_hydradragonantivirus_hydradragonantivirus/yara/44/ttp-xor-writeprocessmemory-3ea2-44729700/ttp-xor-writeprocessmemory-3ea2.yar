rule TTP_XOR_WriteProcessMemory_3ea2 {
  strings:
    $key_3ea2 = { 69 d0 [2] 5b f2 [2] 5d c7 [2] 73 c7 [2] 4c db }

  condition:
    any of them
}