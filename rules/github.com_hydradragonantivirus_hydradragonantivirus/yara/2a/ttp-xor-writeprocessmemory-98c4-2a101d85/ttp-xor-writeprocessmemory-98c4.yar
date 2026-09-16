rule TTP_XOR_WriteProcessMemory_98c4 {
  strings:
    $key_98c4 = { cf b6 [2] fd 94 [2] fb a1 [2] d5 a1 [2] ea bd }

  condition:
    any of them
}