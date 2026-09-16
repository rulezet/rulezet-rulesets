rule TTP_XOR_WriteProcessMemory_5afb {
  strings:
    $key_5afb = { 0d 89 [2] 3f ab [2] 39 9e [2] 17 9e [2] 28 82 }

  condition:
    any of them
}