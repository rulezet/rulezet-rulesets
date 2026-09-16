rule TTP_XOR_WriteProcessMemory_468d {
  strings:
    $key_468d = { 11 ff [2] 23 dd [2] 25 e8 [2] 0b e8 [2] 34 f4 }

  condition:
    any of them
}