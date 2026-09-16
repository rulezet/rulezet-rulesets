rule TTP_XOR_WriteProcessMemory_723c {
  strings:
    $key_723c = { 25 4e [2] 17 6c [2] 11 59 [2] 3f 59 [2] 00 45 }

  condition:
    any of them
}