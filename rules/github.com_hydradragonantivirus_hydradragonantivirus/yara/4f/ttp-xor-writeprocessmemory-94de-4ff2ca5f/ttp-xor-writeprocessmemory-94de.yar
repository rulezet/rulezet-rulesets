rule TTP_XOR_WriteProcessMemory_94de {
  strings:
    $key_94de = { c3 ac [2] f1 8e [2] f7 bb [2] d9 bb [2] e6 a7 }

  condition:
    any of them
}