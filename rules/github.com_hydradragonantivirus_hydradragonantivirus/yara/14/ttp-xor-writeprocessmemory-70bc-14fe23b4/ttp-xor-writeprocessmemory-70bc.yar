rule TTP_XOR_WriteProcessMemory_70bc {
  strings:
    $key_70bc = { 27 ce [2] 15 ec [2] 13 d9 [2] 3d d9 [2] 02 c5 }

  condition:
    any of them
}