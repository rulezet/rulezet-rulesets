rule TTP_XOR_WriteProcessMemory_4db8 {
  strings:
    $key_4db8 = { 1a ca [2] 28 e8 [2] 2e dd [2] 00 dd [2] 3f c1 }

  condition:
    any of them
}