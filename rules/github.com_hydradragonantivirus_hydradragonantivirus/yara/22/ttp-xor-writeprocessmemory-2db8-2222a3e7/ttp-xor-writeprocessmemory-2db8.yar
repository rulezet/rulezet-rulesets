rule TTP_XOR_WriteProcessMemory_2db8 {
  strings:
    $key_2db8 = { 7a ca [2] 48 e8 [2] 4e dd [2] 60 dd [2] 5f c1 }

  condition:
    any of them
}