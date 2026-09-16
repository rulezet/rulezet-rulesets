rule TTP_XOR_WriteProcessMemory_707e {
  strings:
    $key_707e = { 27 0c [2] 15 2e [2] 13 1b [2] 3d 1b [2] 02 07 }

  condition:
    any of them
}