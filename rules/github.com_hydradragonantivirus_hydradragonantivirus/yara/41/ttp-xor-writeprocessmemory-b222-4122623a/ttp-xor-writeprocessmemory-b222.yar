rule TTP_XOR_WriteProcessMemory_b222 {
  strings:
    $key_b222 = { e5 50 [2] d7 72 [2] d1 47 [2] ff 47 [2] c0 5b }

  condition:
    any of them
}