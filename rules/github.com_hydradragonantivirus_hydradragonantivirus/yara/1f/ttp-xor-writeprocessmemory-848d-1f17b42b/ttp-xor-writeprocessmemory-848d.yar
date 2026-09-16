rule TTP_XOR_WriteProcessMemory_848d {
  strings:
    $key_848d = { d3 ff [2] e1 dd [2] e7 e8 [2] c9 e8 [2] f6 f4 }

  condition:
    any of them
}