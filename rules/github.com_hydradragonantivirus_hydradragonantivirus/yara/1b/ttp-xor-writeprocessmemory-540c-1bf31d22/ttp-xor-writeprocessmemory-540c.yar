rule TTP_XOR_WriteProcessMemory_540c {
  strings:
    $key_540c = { 03 7e [2] 31 5c [2] 37 69 [2] 19 69 [2] 26 75 }

  condition:
    any of them
}