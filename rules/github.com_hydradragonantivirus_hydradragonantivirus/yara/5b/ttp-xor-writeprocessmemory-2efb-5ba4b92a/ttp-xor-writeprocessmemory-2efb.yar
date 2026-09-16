rule TTP_XOR_WriteProcessMemory_2efb {
  strings:
    $key_2efb = { 79 89 [2] 4b ab [2] 4d 9e [2] 63 9e [2] 5c 82 }

  condition:
    any of them
}