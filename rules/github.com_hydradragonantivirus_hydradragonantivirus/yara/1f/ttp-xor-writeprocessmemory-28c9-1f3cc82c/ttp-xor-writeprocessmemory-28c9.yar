rule TTP_XOR_WriteProcessMemory_28c9 {
  strings:
    $key_28c9 = { 7f bb [2] 4d 99 [2] 4b ac [2] 65 ac [2] 5a b0 }

  condition:
    any of them
}