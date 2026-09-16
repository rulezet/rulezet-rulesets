rule TTP_XOR_WriteProcessMemory_581c {
  strings:
    $key_581c = { 0f 6e [2] 3d 4c [2] 3b 79 [2] 15 79 [2] 2a 65 }

  condition:
    any of them
}