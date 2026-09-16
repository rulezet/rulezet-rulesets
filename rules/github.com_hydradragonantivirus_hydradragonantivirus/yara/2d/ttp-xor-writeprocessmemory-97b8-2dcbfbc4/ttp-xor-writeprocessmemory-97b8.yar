rule TTP_XOR_WriteProcessMemory_97b8 {
  strings:
    $key_97b8 = { c0 ca [2] f2 e8 [2] f4 dd [2] da dd [2] e5 c1 }

  condition:
    any of them
}