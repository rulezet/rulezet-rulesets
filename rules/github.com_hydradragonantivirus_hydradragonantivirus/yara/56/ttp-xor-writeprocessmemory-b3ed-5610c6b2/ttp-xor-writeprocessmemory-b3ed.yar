rule TTP_XOR_WriteProcessMemory_b3ed {
  strings:
    $key_b3ed = { e4 9f [2] d6 bd [2] d0 88 [2] fe 88 [2] c1 94 }

  condition:
    any of them
}