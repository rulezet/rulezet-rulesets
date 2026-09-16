rule TTP_XOR_WriteProcessMemory_c68d {
  strings:
    $key_c68d = { 91 ff [2] a3 dd [2] a5 e8 [2] 8b e8 [2] b4 f4 }

  condition:
    any of them
}