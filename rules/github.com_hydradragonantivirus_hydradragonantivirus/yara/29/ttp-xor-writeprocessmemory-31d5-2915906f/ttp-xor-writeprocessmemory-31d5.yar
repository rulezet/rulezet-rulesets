rule TTP_XOR_WriteProcessMemory_31d5 {
  strings:
    $key_31d5 = { 66 a7 [2] 54 85 [2] 52 b0 [2] 7c b0 [2] 43 ac }

  condition:
    any of them
}