rule TTP_XOR_WriteProcessMemory_6a2e {
  strings:
    $key_6a2e = { 3d 5c [2] 0f 7e [2] 09 4b [2] 27 4b [2] 18 57 }

  condition:
    any of them
}