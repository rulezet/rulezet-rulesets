rule TTP_XOR_WriteProcessMemory_678d {
  strings:
    $key_678d = { 30 ff [2] 02 dd [2] 04 e8 [2] 2a e8 [2] 15 f4 }

  condition:
    any of them
}