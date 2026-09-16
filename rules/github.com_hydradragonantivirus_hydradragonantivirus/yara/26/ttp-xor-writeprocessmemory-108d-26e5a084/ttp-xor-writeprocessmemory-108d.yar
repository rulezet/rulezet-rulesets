rule TTP_XOR_WriteProcessMemory_108d {
  strings:
    $key_108d = { 47 ff [2] 75 dd [2] 73 e8 [2] 5d e8 [2] 62 f4 }

  condition:
    any of them
}