rule TTP_XOR_WriteProcessMemory_333e {
  strings:
    $key_333e = { 64 4c [2] 56 6e [2] 50 5b [2] 7e 5b [2] 41 47 }

  condition:
    any of them
}