rule TTP_XOR_WriteProcessMemory_478d {
  strings:
    $key_478d = { 10 ff [2] 22 dd [2] 24 e8 [2] 0a e8 [2] 35 f4 }

  condition:
    any of them
}