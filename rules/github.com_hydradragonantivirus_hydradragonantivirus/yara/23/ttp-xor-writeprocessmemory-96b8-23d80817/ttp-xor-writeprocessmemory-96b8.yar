rule TTP_XOR_WriteProcessMemory_96b8 {
  strings:
    $key_96b8 = { c1 ca [2] f3 e8 [2] f5 dd [2] db dd [2] e4 c1 }

  condition:
    any of them
}