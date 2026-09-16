rule TTP_XOR_WriteProcessMemory_dc8d {
  strings:
    $key_dc8d = { 8b ff [2] b9 dd [2] bf e8 [2] 91 e8 [2] ae f4 }

  condition:
    any of them
}