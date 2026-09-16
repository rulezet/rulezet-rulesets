rule TTP_XOR_WriteProcessMemory_37b8 {
  strings:
    $key_37b8 = { 60 ca [2] 52 e8 [2] 54 dd [2] 7a dd [2] 45 c1 }

  condition:
    any of them
}