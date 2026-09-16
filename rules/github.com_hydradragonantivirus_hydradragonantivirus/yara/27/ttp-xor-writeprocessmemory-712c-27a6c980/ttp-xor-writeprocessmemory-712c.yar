rule TTP_XOR_WriteProcessMemory_712c {
  strings:
    $key_712c = { 26 5e [2] 14 7c [2] 12 49 [2] 3c 49 [2] 03 55 }

  condition:
    any of them
}