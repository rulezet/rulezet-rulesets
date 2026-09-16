rule TTP_XOR_WriteProcessMemory_373e {
  strings:
    $key_373e = { 60 4c [2] 52 6e [2] 54 5b [2] 7a 5b [2] 45 47 }

  condition:
    any of them
}