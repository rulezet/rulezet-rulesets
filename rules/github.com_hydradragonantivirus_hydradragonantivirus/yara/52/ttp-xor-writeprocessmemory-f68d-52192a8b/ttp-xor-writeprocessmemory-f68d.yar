rule TTP_XOR_WriteProcessMemory_f68d {
  strings:
    $key_f68d = { a1 ff [2] 93 dd [2] 95 e8 [2] bb e8 [2] 84 f4 }

  condition:
    any of them
}