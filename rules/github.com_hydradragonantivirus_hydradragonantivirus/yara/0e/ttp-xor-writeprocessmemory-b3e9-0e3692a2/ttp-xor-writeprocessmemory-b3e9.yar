rule TTP_XOR_WriteProcessMemory_b3e9 {
  strings:
    $key_b3e9 = { e4 9b [2] d6 b9 [2] d0 8c [2] fe 8c [2] c1 90 }

  condition:
    any of them
}