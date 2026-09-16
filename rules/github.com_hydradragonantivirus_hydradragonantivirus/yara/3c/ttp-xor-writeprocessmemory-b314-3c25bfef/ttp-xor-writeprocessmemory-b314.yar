rule TTP_XOR_WriteProcessMemory_b314 {
  strings:
    $key_b314 = { e4 66 [2] d6 44 [2] d0 71 [2] fe 71 [2] c1 6d }

  condition:
    any of them
}