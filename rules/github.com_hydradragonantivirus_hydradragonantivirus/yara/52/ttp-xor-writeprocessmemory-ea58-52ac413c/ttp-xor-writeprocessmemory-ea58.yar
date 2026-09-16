rule TTP_XOR_WriteProcessMemory_ea58 {
  strings:
    $key_ea58 = { bd 2a [2] 8f 08 [2] 89 3d [2] a7 3d [2] 98 21 }

  condition:
    any of them
}