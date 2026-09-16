rule TTP_XOR_WriteProcessMemory_660c {
  strings:
    $key_660c = { 31 7e [2] 03 5c [2] 05 69 [2] 2b 69 [2] 14 75 }

  condition:
    any of them
}