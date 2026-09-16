rule TTP_XOR_WriteProcessMemory_c38d {
  strings:
    $key_c38d = { 94 ff [2] a6 dd [2] a0 e8 [2] 8e e8 [2] b1 f4 }

  condition:
    any of them
}