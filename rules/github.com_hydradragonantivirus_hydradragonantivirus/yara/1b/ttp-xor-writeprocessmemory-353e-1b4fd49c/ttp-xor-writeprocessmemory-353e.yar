rule TTP_XOR_WriteProcessMemory_353e {
  strings:
    $key_353e = { 62 4c [2] 50 6e [2] 56 5b [2] 78 5b [2] 47 47 }

  condition:
    any of them
}