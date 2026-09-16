rule TTP_XOR_WriteProcessMemory_5838 {
  strings:
    $key_5838 = { 0f 4a [2] 3d 68 [2] 3b 5d [2] 15 5d [2] 2a 41 }

  condition:
    any of them
}