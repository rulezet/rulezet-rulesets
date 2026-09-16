rule TTP_XOR_WriteProcessMemory_502b {
  strings:
    $key_502b = { 07 59 [2] 35 7b [2] 33 4e [2] 1d 4e [2] 22 52 }

  condition:
    any of them
}