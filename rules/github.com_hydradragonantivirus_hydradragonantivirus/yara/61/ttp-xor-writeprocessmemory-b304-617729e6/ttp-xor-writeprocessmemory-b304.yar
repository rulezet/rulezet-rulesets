rule TTP_XOR_WriteProcessMemory_b304 {
  strings:
    $key_b304 = { e4 76 [2] d6 54 [2] d0 61 [2] fe 61 [2] c1 7d }

  condition:
    any of them
}