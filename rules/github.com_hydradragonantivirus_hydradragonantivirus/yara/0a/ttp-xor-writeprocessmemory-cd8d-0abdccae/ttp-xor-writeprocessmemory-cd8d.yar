rule TTP_XOR_WriteProcessMemory_cd8d {
  strings:
    $key_cd8d = { 9a ff [2] a8 dd [2] ae e8 [2] 80 e8 [2] bf f4 }

  condition:
    any of them
}