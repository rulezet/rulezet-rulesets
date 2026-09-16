rule TTP_XOR_WriteProcessMemory_d18d {
  strings:
    $key_d18d = { 86 ff [2] b4 dd [2] b2 e8 [2] 9c e8 [2] a3 f4 }

  condition:
    any of them
}