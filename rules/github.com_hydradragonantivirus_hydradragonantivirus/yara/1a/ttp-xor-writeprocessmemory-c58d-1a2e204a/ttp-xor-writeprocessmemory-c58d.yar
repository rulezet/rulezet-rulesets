rule TTP_XOR_WriteProcessMemory_c58d {
  strings:
    $key_c58d = { 92 ff [2] a0 dd [2] a6 e8 [2] 88 e8 [2] b7 f4 }

  condition:
    any of them
}