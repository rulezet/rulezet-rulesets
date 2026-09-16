rule TTP_XOR_WriteProcessMemory_406b {
  strings:
    $key_406b = { 17 19 [2] 25 3b [2] 23 0e [2] 0d 0e [2] 32 12 }

  condition:
    any of them
}