rule TTP_XOR_WriteProcessMemory_101c {
  strings:
    $key_101c = { 47 6e [2] 75 4c [2] 73 79 [2] 5d 79 [2] 62 65 }

  condition:
    any of them
}