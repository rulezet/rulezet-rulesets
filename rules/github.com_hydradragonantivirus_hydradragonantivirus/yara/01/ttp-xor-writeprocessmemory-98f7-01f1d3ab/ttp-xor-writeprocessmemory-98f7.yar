rule TTP_XOR_WriteProcessMemory_98f7 {
  strings:
    $key_98f7 = { cf 85 [2] fd a7 [2] fb 92 [2] d5 92 [2] ea 8e }

  condition:
    any of them
}