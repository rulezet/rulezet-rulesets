rule TTP_XOR_WriteProcessMemory_078d {
  strings:
    $key_078d = { 50 ff [2] 62 dd [2] 64 e8 [2] 4a e8 [2] 75 f4 }

  condition:
    any of them
}