rule TTP_XOR_WriteProcessMemory_058d {
  strings:
    $key_058d = { 52 ff [2] 60 dd [2] 66 e8 [2] 48 e8 [2] 77 f4 }

  condition:
    any of them
}