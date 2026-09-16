rule TTP_XOR_WriteProcessMemory_582b {
  strings:
    $key_582b = { 0f 59 [2] 3d 7b [2] 3b 4e [2] 15 4e [2] 2a 52 }

  condition:
    any of them
}