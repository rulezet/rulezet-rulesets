rule TTP_XOR_WriteProcessMemory_3d6c {
  strings:
    $key_3d6c = { 6a 1e [2] 58 3c [2] 5e 09 [2] 70 09 [2] 4f 15 }

  condition:
    any of them
}