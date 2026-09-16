rule TTP_XOR_WriteProcessMemory_d78d {
  strings:
    $key_d78d = { 80 ff [2] b2 dd [2] b4 e8 [2] 9a e8 [2] a5 f4 }

  condition:
    any of them
}