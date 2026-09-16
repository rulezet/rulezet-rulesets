rule TTP_XOR_WriteProcessMemory_581e {
  strings:
    $key_581e = { 0f 6c [2] 3d 4e [2] 3b 7b [2] 15 7b [2] 2a 67 }

  condition:
    any of them
}