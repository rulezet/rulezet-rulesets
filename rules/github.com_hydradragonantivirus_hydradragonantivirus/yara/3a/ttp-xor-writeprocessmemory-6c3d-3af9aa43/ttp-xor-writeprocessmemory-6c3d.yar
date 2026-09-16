rule TTP_XOR_WriteProcessMemory_6c3d {
  strings:
    $key_6c3d = { 3b 4f [2] 09 6d [2] 0f 58 [2] 21 58 [2] 1e 44 }

  condition:
    any of them
}