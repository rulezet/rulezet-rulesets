rule TTP_XOR_WriteProcessMemory_71d5 {
  strings:
    $key_71d5 = { 26 a7 [2] 14 85 [2] 12 b0 [2] 3c b0 [2] 03 ac }

  condition:
    any of them
}