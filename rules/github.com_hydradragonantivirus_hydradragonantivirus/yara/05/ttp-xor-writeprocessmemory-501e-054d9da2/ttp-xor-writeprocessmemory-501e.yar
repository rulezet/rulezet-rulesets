rule TTP_XOR_WriteProcessMemory_501e {
  strings:
    $key_501e = { 07 6c [2] 35 4e [2] 33 7b [2] 1d 7b [2] 22 67 }

  condition:
    any of them
}