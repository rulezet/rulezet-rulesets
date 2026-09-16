rule TTP_XOR_WriteProcessMemory_6a3e {
  strings:
    $key_6a3e = { 3d 4c [2] 0f 6e [2] 09 5b [2] 27 5b [2] 18 47 }

  condition:
    any of them
}