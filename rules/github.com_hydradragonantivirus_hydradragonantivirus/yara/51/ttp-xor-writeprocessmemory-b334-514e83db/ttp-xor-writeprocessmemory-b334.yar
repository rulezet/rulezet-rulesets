rule TTP_XOR_WriteProcessMemory_b334 {
  strings:
    $key_b334 = { e4 46 [2] d6 64 [2] d0 51 [2] fe 51 [2] c1 4d }

  condition:
    any of them
}