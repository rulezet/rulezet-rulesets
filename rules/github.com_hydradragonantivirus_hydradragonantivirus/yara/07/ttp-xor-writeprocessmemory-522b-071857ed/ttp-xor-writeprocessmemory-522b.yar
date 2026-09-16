rule TTP_XOR_WriteProcessMemory_522b {
  strings:
    $key_522b = { 05 59 [2] 37 7b [2] 31 4e [2] 1f 4e [2] 20 52 }

  condition:
    any of them
}