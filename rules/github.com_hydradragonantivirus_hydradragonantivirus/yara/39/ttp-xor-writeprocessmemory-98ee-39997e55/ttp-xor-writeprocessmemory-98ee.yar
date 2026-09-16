rule TTP_XOR_WriteProcessMemory_98ee {
  strings:
    $key_98ee = { cf 9c [2] fd be [2] fb 8b [2] d5 8b [2] ea 97 }

  condition:
    any of them
}