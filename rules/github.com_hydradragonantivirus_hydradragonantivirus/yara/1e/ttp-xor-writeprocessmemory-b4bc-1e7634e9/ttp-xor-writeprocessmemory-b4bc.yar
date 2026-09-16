rule TTP_XOR_WriteProcessMemory_b4bc {
  strings:
    $key_b4bc = { e3 ce [2] d1 ec [2] d7 d9 [2] f9 d9 [2] c6 c5 }

  condition:
    any of them
}