rule TTP_XOR_WriteProcessMemory_018d {
  strings:
    $key_018d = { 56 ff [2] 64 dd [2] 62 e8 [2] 4c e8 [2] 73 f4 }

  condition:
    any of them
}