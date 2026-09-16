rule TTP_XOR_WriteProcessMemory_036c {
  strings:
    $key_036c = { 54 1e [2] 66 3c [2] 60 09 [2] 4e 09 [2] 71 15 }

  condition:
    any of them
}