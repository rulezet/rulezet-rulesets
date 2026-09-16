rule TTP_XOR_WriteProcessMemory_433e {
  strings:
    $key_433e = { 14 4c [2] 26 6e [2] 20 5b [2] 0e 5b [2] 31 47 }

  condition:
    any of them
}