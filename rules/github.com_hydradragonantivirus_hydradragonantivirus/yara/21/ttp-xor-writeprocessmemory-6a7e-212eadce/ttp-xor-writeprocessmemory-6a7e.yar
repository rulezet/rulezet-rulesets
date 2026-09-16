rule TTP_XOR_WriteProcessMemory_6a7e {
  strings:
    $key_6a7e = { 3d 0c [2] 0f 2e [2] 09 1b [2] 27 1b [2] 18 07 }

  condition:
    any of them
}