rule TTP_XOR_WriteProcessMemory_38c9 {
  strings:
    $key_38c9 = { 6f bb [2] 5d 99 [2] 5b ac [2] 75 ac [2] 4a b0 }

  condition:
    any of them
}