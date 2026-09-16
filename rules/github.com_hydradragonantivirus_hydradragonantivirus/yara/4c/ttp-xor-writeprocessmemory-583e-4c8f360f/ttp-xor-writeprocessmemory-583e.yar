rule TTP_XOR_WriteProcessMemory_583e {
  strings:
    $key_583e = { 0f 4c [2] 3d 6e [2] 3b 5b [2] 15 5b [2] 2a 47 }

  condition:
    any of them
}