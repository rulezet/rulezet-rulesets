rule TTP_XOR_WriteProcessMemory_a567 {
  strings:
    $key_a567 = { f2 15 [2] c0 37 [2] c6 02 [2] e8 02 [2] d7 1e }

  condition:
    any of them
}