rule TTP_XOR_WriteProcessMemory_458d {
  strings:
    $key_458d = { 12 ff [2] 20 dd [2] 26 e8 [2] 08 e8 [2] 37 f4 }

  condition:
    any of them
}