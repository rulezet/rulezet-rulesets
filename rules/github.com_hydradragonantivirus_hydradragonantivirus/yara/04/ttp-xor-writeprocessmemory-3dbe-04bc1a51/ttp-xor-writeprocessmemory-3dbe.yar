rule TTP_XOR_WriteProcessMemory_3dbe {
  strings:
    $key_3dbe = { 6a cc [2] 58 ee [2] 5e db [2] 70 db [2] 4f c7 }

  condition:
    any of them
}