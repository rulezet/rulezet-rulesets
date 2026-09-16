rule TTP_XOR_WriteProcessMemory_98f1 {
  strings:
    $key_98f1 = { cf 83 [2] fd a1 [2] fb 94 [2] d5 94 [2] ea 88 }

  condition:
    any of them
}