rule TTP_XOR_WriteProcessMemory_542c {
  strings:
    $key_542c = { 03 5e [2] 31 7c [2] 37 49 [2] 19 49 [2] 26 55 }

  condition:
    any of them
}