rule TTP_XOR_WriteProcessMemory_a287 {
  strings:
    $key_a287 = { f5 f5 [2] c7 d7 [2] c1 e2 [2] ef e2 [2] d0 fe }

  condition:
    any of them
}