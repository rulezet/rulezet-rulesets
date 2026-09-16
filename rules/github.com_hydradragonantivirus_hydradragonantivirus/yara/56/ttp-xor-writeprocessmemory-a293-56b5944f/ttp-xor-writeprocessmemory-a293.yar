rule TTP_XOR_WriteProcessMemory_a293 {
  strings:
    $key_a293 = { f5 e1 [2] c7 c3 [2] c1 f6 [2] ef f6 [2] d0 ea }

  condition:
    any of them
}