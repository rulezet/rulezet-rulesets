rule TTP_XOR_WriteProcessMemory_b324 {
  strings:
    $key_b324 = { e4 56 [2] d6 74 [2] d0 41 [2] fe 41 [2] c1 5d }

  condition:
    any of them
}