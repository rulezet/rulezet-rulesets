rule TTP_XOR_WriteProcessMemory_623e {
  strings:
    $key_623e = { 35 4c [2] 07 6e [2] 01 5b [2] 2f 5b [2] 10 47 }

  condition:
    any of them
}