rule TTP_XOR_WriteProcessMemory_b326 {
  strings:
    $key_b326 = { e4 54 [2] d6 76 [2] d0 43 [2] fe 43 [2] c1 5f }

  condition:
    any of them
}