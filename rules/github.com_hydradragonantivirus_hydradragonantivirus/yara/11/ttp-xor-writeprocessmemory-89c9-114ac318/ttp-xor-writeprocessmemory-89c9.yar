rule TTP_XOR_WriteProcessMemory_89c9 {
  strings:
    $key_89c9 = { de bb [2] ec 99 [2] ea ac [2] c4 ac [2] fb b0 }

  condition:
    any of them
}