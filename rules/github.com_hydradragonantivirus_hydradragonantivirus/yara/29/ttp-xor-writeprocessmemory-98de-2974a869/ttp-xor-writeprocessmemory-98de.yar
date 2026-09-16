rule TTP_XOR_WriteProcessMemory_98de {
  strings:
    $key_98de = { cf ac [2] fd 8e [2] fb bb [2] d5 bb [2] ea a7 }

  condition:
    any of them
}