rule TTP_XOR_WriteProcessMemory_383e {
  strings:
    $key_383e = { 6f 4c [2] 5d 6e [2] 5b 5b [2] 75 5b [2] 4a 47 }

  condition:
    any of them
}