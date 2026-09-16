rule TTP_XOR_WriteProcessMemory_98fc {
  strings:
    $key_98fc = { cf 8e [2] fd ac [2] fb 99 [2] d5 99 [2] ea 85 }

  condition:
    any of them
}