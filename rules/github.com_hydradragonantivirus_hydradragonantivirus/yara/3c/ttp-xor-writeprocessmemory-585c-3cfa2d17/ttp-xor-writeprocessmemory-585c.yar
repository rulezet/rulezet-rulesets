rule TTP_XOR_WriteProcessMemory_585c {
  strings:
    $key_585c = { 0f 2e [2] 3d 0c [2] 3b 39 [2] 15 39 [2] 2a 25 }

  condition:
    any of them
}