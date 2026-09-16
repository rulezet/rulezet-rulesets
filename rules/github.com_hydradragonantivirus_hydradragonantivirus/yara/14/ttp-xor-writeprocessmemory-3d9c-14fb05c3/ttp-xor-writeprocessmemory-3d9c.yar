rule TTP_XOR_WriteProcessMemory_3d9c {
  strings:
    $key_3d9c = { 6a ee [2] 58 cc [2] 5e f9 [2] 70 f9 [2] 4f e5 }

  condition:
    any of them
}