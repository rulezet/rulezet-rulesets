rule TTP_XOR_WriteProcessMemory_98f4 {
  strings:
    $key_98f4 = { cf 86 [2] fd a4 [2] fb 91 [2] d5 91 [2] ea 8d }

  condition:
    any of them
}