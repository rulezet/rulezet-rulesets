rule TTP_XOR_WriteProcessMemory_024e {
  strings:
    $key_024e = { 55 3c [2] 67 1e [2] 61 2b [2] 4f 2b [2] 70 37 }

  condition:
    any of them
}