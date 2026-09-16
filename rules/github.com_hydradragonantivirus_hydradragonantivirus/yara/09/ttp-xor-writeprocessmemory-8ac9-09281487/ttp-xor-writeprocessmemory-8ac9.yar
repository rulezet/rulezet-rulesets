rule TTP_XOR_WriteProcessMemory_8ac9 {
  strings:
    $key_8ac9 = { dd bb [2] ef 99 [2] e9 ac [2] c7 ac [2] f8 b0 }

  condition:
    any of them
}