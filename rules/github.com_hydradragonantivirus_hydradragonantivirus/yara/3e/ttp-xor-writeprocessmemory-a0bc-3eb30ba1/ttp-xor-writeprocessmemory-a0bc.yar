rule TTP_XOR_WriteProcessMemory_a0bc {
  strings:
    $key_a0bc = { f7 ce [2] c5 ec [2] c3 d9 [2] ed d9 [2] d2 c5 }

  condition:
    any of them
}