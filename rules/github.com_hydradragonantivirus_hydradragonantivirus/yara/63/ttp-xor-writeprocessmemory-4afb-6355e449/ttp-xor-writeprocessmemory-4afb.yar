rule TTP_XOR_WriteProcessMemory_4afb {
  strings:
    $key_4afb = { 1d 89 [2] 2f ab [2] 29 9e [2] 07 9e [2] 38 82 }

  condition:
    any of them
}