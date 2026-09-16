rule TTP_XOR_WriteProcessMemory_6a4c {
  strings:
    $key_6a4c = { 3d 3e [2] 0f 1c [2] 09 29 [2] 27 29 [2] 18 35 }

  condition:
    any of them
}