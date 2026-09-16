rule TTP_XOR_WriteProcessMemory_87b8 {
  strings:
    $key_87b8 = { d0 ca [2] e2 e8 [2] e4 dd [2] ca dd [2] f5 c1 }

  condition:
    any of them
}