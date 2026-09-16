rule TTP_XOR_WriteProcessMemory_502e {
  strings:
    $key_502e = { 07 5c [2] 35 7e [2] 33 4b [2] 1d 4b [2] 22 57 }

  condition:
    any of them
}