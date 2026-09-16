rule TTP_XOR_WriteProcessMemory_66b8 {
  strings:
    $key_66b8 = { 31 ca [2] 03 e8 [2] 05 dd [2] 2b dd [2] 14 c1 }

  condition:
    any of them
}