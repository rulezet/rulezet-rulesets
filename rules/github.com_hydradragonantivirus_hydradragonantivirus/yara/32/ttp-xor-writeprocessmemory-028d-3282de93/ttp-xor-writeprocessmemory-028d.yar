rule TTP_XOR_WriteProcessMemory_028d {
  strings:
    $key_028d = { 55 ff [2] 67 dd [2] 61 e8 [2] 4f e8 [2] 70 f4 }

  condition:
    any of them
}