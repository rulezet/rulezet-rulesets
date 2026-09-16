rule TTP_XOR_WriteProcessMemory_8fc9 {
  strings:
    $key_8fc9 = { d8 bb [2] ea 99 [2] ec ac [2] c2 ac [2] fd b0 }

  condition:
    any of them
}