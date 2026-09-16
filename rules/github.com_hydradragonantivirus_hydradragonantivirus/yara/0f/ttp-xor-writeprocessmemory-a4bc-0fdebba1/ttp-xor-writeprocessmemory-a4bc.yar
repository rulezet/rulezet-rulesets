rule TTP_XOR_WriteProcessMemory_a4bc {
  strings:
    $key_a4bc = { f3 ce [2] c1 ec [2] c7 d9 [2] e9 d9 [2] d6 c5 }

  condition:
    any of them
}