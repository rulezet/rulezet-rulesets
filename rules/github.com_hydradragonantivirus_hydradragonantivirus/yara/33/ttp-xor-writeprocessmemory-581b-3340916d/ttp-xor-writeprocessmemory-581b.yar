rule TTP_XOR_WriteProcessMemory_581b {
  strings:
    $key_581b = { 0f 69 [2] 3d 4b [2] 3b 7e [2] 15 7e [2] 2a 62 }

  condition:
    any of them
}