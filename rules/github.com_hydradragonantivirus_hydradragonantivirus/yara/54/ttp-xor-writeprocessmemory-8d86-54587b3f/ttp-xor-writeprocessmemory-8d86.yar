rule TTP_XOR_WriteProcessMemory_8d86 {
  strings:
    $key_8d86 = { da f4 [2] e8 d6 [2] ee e3 [2] c0 e3 [2] ff ff }

  condition:
    any of them
}