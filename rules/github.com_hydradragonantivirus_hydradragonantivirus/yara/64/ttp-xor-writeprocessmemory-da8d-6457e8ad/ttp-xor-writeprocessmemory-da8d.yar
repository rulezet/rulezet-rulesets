rule TTP_XOR_WriteProcessMemory_da8d {
  strings:
    $key_da8d = { 8d ff [2] bf dd [2] b9 e8 [2] 97 e8 [2] a8 f4 }

  condition:
    any of them
}