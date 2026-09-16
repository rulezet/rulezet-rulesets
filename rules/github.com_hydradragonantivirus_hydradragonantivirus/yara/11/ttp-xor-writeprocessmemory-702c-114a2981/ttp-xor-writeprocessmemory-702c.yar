rule TTP_XOR_WriteProcessMemory_702c {
  strings:
    $key_702c = { 27 5e [2] 15 7c [2] 13 49 [2] 3d 49 [2] 02 55 }

  condition:
    any of them
}