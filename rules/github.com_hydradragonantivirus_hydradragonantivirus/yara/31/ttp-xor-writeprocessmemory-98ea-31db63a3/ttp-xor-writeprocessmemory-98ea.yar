rule TTP_XOR_WriteProcessMemory_98ea {
  strings:
    $key_98ea = { cf 98 [2] fd ba [2] fb 8f [2] d5 8f [2] ea 93 }

  condition:
    any of them
}