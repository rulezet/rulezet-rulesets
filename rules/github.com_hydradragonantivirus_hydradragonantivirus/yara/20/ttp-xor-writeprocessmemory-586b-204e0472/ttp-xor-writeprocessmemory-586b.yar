rule TTP_XOR_WriteProcessMemory_586b {
  strings:
    $key_586b = { 0f 19 [2] 3d 3b [2] 3b 0e [2] 15 0e [2] 2a 12 }

  condition:
    any of them
}