rule TTP_XOR_WriteProcessMemory_0512 {
  strings:
    $key_0512 = { 52 60 [2] 60 42 [2] 66 77 [2] 48 77 [2] 77 6b }

  condition:
    any of them
}