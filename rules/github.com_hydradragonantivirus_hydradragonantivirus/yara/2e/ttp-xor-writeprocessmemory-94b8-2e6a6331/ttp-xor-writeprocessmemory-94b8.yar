rule TTP_XOR_WriteProcessMemory_94b8 {
  strings:
    $key_94b8 = { c3 ca [2] f1 e8 [2] f7 dd [2] d9 dd [2] e6 c1 }

  condition:
    any of them
}