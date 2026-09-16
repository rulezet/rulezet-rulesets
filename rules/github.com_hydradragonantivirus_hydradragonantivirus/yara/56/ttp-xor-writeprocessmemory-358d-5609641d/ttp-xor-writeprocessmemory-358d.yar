rule TTP_XOR_WriteProcessMemory_358d {
  strings:
    $key_358d = { 62 ff [2] 50 dd [2] 56 e8 [2] 78 e8 [2] 47 f4 }

  condition:
    any of them
}