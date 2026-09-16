rule TTP_XOR_WriteProcessMemory_98c0 {
  strings:
    $key_98c0 = { cf b2 [2] fd 90 [2] fb a5 [2] d5 a5 [2] ea b9 }

  condition:
    any of them
}