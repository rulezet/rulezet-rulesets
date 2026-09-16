rule TTP_XOR_WriteProcessMemory_708b {
  strings:
    $key_708b = { 27 f9 [2] 15 db [2] 13 ee [2] 3d ee [2] 02 f2 }

  condition:
    any of them
}