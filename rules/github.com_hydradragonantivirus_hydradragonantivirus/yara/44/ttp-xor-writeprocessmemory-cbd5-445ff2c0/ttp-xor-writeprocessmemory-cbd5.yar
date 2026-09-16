rule TTP_XOR_WriteProcessMemory_cbd5 {
  strings:
    $key_cbd5 = { 9c a7 [2] ae 85 [2] a8 b0 [2] 86 b0 [2] b9 ac }

  condition:
    any of them
}