rule TTP_XOR_WriteProcessMemory_80b8 {
  strings:
    $key_80b8 = { d7 ca [2] e5 e8 [2] e3 dd [2] cd dd [2] f2 c1 }

  condition:
    any of them
}