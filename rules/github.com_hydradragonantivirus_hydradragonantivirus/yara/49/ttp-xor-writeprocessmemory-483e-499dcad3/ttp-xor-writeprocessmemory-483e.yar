rule TTP_XOR_WriteProcessMemory_483e {
  strings:
    $key_483e = { 1f 4c [2] 2d 6e [2] 2b 5b [2] 05 5b [2] 3a 47 }

  condition:
    any of them
}