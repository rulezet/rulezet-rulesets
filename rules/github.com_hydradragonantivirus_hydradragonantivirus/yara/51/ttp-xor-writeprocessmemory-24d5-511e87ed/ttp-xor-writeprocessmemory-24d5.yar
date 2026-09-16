rule TTP_XOR_WriteProcessMemory_24d5 {
  strings:
    $key_24d5 = { 73 a7 [2] 41 85 [2] 47 b0 [2] 69 b0 [2] 56 ac }

  condition:
    any of them
}