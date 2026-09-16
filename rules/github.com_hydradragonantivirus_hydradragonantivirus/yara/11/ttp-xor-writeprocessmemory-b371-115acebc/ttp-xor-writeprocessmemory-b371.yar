rule TTP_XOR_WriteProcessMemory_b371 {
  strings:
    $key_b371 = { e4 03 [2] d6 21 [2] d0 14 [2] fe 14 [2] c1 08 }

  condition:
    any of them
}