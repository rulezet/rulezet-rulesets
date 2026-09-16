rule TTP_XOR_WriteProcessMemory_cbc0 {
  strings:
    $key_cbc0 = { 9c b2 [2] ae 90 [2] a8 a5 [2] 86 a5 [2] b9 b9 }

  condition:
    any of them
}