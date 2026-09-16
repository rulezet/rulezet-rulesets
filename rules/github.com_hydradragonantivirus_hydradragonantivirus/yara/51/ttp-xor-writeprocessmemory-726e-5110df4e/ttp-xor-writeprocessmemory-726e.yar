rule TTP_XOR_WriteProcessMemory_726e {
  strings:
    $key_726e = { 25 1c [2] 17 3e [2] 11 0b [2] 3f 0b [2] 00 17 }

  condition:
    any of them
}