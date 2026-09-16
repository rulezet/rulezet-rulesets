rule TTP_XOR_WriteProcessMemory_70dc {
  strings:
    $key_70dc = { 27 ae [2] 15 8c [2] 13 b9 [2] 3d b9 [2] 02 a5 }

  condition:
    any of them
}