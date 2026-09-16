rule TTP_XOR_WriteProcessMemory_2ffb {
  strings:
    $key_2ffb = { 78 89 [2] 4a ab [2] 4c 9e [2] 62 9e [2] 5d 82 }

  condition:
    any of them
}