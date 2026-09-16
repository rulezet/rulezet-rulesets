rule TTP_XOR_WriteProcessMemory_003e {
  strings:
    $key_003e = { 57 4c [2] 65 6e [2] 63 5b [2] 4d 5b [2] 72 47 }

  condition:
    any of them
}