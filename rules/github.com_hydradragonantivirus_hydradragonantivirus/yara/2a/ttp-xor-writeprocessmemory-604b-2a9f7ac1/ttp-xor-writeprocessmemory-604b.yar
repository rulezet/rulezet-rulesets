rule TTP_XOR_WriteProcessMemory_604b {
  strings:
    $key_604b = { 37 39 [2] 05 1b [2] 03 2e [2] 2d 2e [2] 12 32 }

  condition:
    any of them
}