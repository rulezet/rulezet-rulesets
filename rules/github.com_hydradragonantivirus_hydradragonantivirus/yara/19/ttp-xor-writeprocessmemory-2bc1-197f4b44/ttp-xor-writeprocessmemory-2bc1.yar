rule TTP_XOR_WriteProcessMemory_2bc1 {
  strings:
    $key_2bc1 = { 7c b3 [2] 4e 91 [2] 48 a4 [2] 66 a4 [2] 59 b8 }

  condition:
    any of them
}