rule TTP_XOR_WriteProcessMemory_78c9 {
  strings:
    $key_78c9 = { 2f bb [2] 1d 99 [2] 1b ac [2] 35 ac [2] 0a b0 }

  condition:
    any of them
}