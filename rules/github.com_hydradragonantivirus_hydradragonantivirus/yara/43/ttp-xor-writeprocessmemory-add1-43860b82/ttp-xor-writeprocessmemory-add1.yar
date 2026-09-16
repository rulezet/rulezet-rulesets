rule TTP_XOR_WriteProcessMemory_add1 {
  strings:
    $key_add1 = { fa a3 [2] c8 81 [2] ce b4 [2] e0 b4 [2] df a8 }

  condition:
    any of them
}