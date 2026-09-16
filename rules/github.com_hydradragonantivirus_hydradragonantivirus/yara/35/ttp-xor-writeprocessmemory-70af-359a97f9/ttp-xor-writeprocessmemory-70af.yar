rule TTP_XOR_WriteProcessMemory_70af {
  strings:
    $key_70af = { 27 dd [2] 15 ff [2] 13 ca [2] 3d ca [2] 02 d6 }

  condition:
    any of them
}