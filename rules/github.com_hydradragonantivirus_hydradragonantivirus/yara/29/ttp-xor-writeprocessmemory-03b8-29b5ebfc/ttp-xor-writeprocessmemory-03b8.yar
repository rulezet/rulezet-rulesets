rule TTP_XOR_WriteProcessMemory_03b8 {
  strings:
    $key_03b8 = { 54 ca [2] 66 e8 [2] 60 dd [2] 4e dd [2] 71 c1 }

  condition:
    any of them
}