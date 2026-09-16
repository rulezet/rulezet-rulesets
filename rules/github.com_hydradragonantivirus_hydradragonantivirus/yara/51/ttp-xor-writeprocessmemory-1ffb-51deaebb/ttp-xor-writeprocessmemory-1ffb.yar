rule TTP_XOR_WriteProcessMemory_1ffb {
  strings:
    $key_1ffb = { 48 89 [2] 7a ab [2] 7c 9e [2] 52 9e [2] 6d 82 }

  condition:
    any of them
}