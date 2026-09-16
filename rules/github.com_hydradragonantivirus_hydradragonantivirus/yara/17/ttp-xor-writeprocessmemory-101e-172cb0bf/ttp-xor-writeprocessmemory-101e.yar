rule TTP_XOR_WriteProcessMemory_101e {
  strings:
    $key_101e = { 47 6c [2] 75 4e [2] 73 7b [2] 5d 7b [2] 62 67 }

  condition:
    any of them
}