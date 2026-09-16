rule TTP_XOR_WriteProcessMemory_8fde {
  strings:
    $key_8fde = { d8 ac [2] ea 8e [2] ec bb [2] c2 bb [2] fd a7 }

  condition:
    any of them
}