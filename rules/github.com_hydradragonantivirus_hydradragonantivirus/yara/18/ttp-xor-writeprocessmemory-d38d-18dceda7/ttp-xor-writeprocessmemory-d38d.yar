rule TTP_XOR_WriteProcessMemory_d38d {
  strings:
    $key_d38d = { 84 ff [2] b6 dd [2] b0 e8 [2] 9e e8 [2] a1 f4 }

  condition:
    any of them
}