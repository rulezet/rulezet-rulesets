rule TTP_XOR_WriteProcessMemory_b5bc {
  strings:
    $key_b5bc = { e2 ce [2] d0 ec [2] d6 d9 [2] f8 d9 [2] c7 c5 }

  condition:
    any of them
}