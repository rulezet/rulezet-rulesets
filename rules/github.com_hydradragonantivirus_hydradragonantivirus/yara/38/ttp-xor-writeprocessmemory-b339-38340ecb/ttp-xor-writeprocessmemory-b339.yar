rule TTP_XOR_WriteProcessMemory_b339 {
  strings:
    $key_b339 = { e4 4b [2] d6 69 [2] d0 5c [2] fe 5c [2] c1 40 }

  condition:
    any of them
}