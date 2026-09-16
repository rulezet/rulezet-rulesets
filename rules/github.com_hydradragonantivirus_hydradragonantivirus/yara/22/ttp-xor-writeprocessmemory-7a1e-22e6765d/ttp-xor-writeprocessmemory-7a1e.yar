rule TTP_XOR_WriteProcessMemory_7a1e {
  strings:
    $key_7a1e = { 2d 6c [2] 1f 4e [2] 19 7b [2] 37 7b [2] 08 67 }

  condition:
    any of them
}