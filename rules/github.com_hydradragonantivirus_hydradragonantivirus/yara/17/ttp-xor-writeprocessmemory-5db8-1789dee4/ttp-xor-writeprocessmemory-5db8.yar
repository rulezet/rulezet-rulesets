rule TTP_XOR_WriteProcessMemory_5db8 {
  strings:
    $key_5db8 = { 0a ca [2] 38 e8 [2] 3e dd [2] 10 dd [2] 2f c1 }

  condition:
    any of them
}