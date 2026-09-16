rule TTP_XOR_WriteProcessMemory_709c {
  strings:
    $key_709c = { 27 ee [2] 15 cc [2] 13 f9 [2] 3d f9 [2] 02 e5 }

  condition:
    any of them
}