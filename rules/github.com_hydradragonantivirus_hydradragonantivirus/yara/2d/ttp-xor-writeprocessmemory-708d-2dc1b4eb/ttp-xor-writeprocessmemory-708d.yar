rule TTP_XOR_WriteProcessMemory_708d {
  strings:
    $key_708d = { 27 ff [2] 15 dd [2] 13 e8 [2] 3d e8 [2] 02 f4 }

  condition:
    any of them
}