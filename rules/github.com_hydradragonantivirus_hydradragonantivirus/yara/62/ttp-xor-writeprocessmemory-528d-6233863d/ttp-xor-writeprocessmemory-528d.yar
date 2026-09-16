rule TTP_XOR_WriteProcessMemory_528d {
  strings:
    $key_528d = { 05 ff [2] 37 dd [2] 31 e8 [2] 1f e8 [2] 20 f4 }

  condition:
    any of them
}