rule TTP_XOR_WriteProcessMemory_704b {
  strings:
    $key_704b = { 27 39 [2] 15 1b [2] 13 2e [2] 3d 2e [2] 02 32 }

  condition:
    any of them
}