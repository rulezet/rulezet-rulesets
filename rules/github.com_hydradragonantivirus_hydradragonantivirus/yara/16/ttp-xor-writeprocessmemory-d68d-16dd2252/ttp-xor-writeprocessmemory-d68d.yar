rule TTP_XOR_WriteProcessMemory_d68d {
  strings:
    $key_d68d = { 81 ff [2] b3 dd [2] b5 e8 [2] 9b e8 [2] a4 f4 }

  condition:
    any of them
}