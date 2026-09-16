rule TTP_XOR_WriteProcessMemory_7a4e {
  strings:
    $key_7a4e = { 2d 3c [2] 1f 1e [2] 19 2b [2] 37 2b [2] 08 37 }

  condition:
    any of them
}