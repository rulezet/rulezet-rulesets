rule TTP_XOR_WriteProcessMemory_cbc1 {
  strings:
    $key_cbc1 = { 9c b3 [2] ae 91 [2] a8 a4 [2] 86 a4 [2] b9 b8 }

  condition:
    any of them
}