rule TTP_XOR_WriteProcessMemory_a3b3 {
  strings:
    $key_a3b3 = { f4 c1 [2] c6 e3 [2] c0 d6 [2] ee d6 [2] d1 ca }

  condition:
    any of them
}