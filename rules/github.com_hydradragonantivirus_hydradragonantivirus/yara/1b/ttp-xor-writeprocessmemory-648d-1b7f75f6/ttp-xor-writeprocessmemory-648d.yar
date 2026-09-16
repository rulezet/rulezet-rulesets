rule TTP_XOR_WriteProcessMemory_648d {
  strings:
    $key_648d = { 33 ff [2] 01 dd [2] 07 e8 [2] 29 e8 [2] 16 f4 }

  condition:
    any of them
}