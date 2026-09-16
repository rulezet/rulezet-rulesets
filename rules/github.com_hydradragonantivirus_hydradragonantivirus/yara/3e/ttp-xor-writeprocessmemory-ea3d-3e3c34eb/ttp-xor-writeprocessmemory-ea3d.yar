rule TTP_XOR_WriteProcessMemory_ea3d {
  strings:
    $key_ea3d = { bd 4f [2] 8f 6d [2] 89 58 [2] a7 58 [2] 98 44 }

  condition:
    any of them
}