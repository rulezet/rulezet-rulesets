rule TTP_XOR_WriteProcessMemory_b19c {
  strings:
    $key_b19c = { e6 ee [2] d4 cc [2] d2 f9 [2] fc f9 [2] c3 e5 }

  condition:
    any of them
}