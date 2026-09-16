rule TTP_XOR_WriteProcessMemory_dbb8 {
  strings:
    $key_dbb8 = { 8c ca [2] be e8 [2] b8 dd [2] 96 dd [2] a9 c1 }

  condition:
    any of them
}