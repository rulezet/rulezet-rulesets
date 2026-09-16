rule TTP_XOR_WriteProcessMemory_31d0 {
  strings:
    $key_31d0 = { 66 a2 [2] 54 80 [2] 52 b5 [2] 7c b5 [2] 43 a9 }

  condition:
    any of them
}