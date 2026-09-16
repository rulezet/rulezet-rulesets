rule TTP_XOR_WriteProcessMemory_f78d {
  strings:
    $key_f78d = { a0 ff [2] 92 dd [2] 94 e8 [2] ba e8 [2] 85 f4 }

  condition:
    any of them
}