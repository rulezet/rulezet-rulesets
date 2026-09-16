rule TTP_XOR_WriteProcessMemory_ddc9 {
  strings:
    $key_ddc9 = { 8a bb [2] b8 99 [2] be ac [2] 90 ac [2] af b0 }

  condition:
    any of them
}