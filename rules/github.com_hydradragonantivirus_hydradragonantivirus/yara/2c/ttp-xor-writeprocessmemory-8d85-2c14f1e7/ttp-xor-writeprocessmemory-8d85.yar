rule TTP_XOR_WriteProcessMemory_8d85 {
  strings:
    $key_8d85 = { da f7 [2] e8 d5 [2] ee e0 [2] c0 e0 [2] ff fc }

  condition:
    any of them
}