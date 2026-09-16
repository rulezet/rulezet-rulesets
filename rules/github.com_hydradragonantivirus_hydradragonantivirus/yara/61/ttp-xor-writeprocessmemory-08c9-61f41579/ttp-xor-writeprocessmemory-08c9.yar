rule TTP_XOR_WriteProcessMemory_08c9 {
  strings:
    $key_08c9 = { 5f bb [2] 6d 99 [2] 6b ac [2] 45 ac [2] 7a b0 }

  condition:
    any of them
}