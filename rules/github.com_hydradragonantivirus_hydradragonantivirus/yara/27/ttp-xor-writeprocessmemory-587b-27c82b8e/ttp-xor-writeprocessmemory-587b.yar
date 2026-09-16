rule TTP_XOR_WriteProcessMemory_587b {
  strings:
    $key_587b = { 0f 09 [2] 3d 2b [2] 3b 1e [2] 15 1e [2] 2a 02 }

  condition:
    any of them
}