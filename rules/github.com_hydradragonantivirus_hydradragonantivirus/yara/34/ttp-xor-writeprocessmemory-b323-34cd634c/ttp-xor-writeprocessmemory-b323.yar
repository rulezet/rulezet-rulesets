rule TTP_XOR_WriteProcessMemory_b323 {
  strings:
    $key_b323 = { e4 51 [2] d6 73 [2] d0 46 [2] fe 46 [2] c1 5a }

  condition:
    any of them
}