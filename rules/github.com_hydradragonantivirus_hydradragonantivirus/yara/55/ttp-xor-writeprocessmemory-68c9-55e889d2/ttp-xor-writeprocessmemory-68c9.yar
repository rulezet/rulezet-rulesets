rule TTP_XOR_WriteProcessMemory_68c9 {
  strings:
    $key_68c9 = { 3f bb [2] 0d 99 [2] 0b ac [2] 25 ac [2] 1a b0 }

  condition:
    any of them
}