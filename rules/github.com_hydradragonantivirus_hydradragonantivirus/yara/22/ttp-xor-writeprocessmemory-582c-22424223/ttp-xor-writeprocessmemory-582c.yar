rule TTP_XOR_WriteProcessMemory_582c {
  strings:
    $key_582c = { 0f 5e [2] 3d 7c [2] 3b 49 [2] 15 49 [2] 2a 55 }

  condition:
    any of them
}