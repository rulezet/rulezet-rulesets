rule TTP_XOR_WriteProcessMemory_7a3e {
  strings:
    $key_7a3e = { 2d 4c [2] 1f 6e [2] 19 5b [2] 37 5b [2] 08 47 }

  condition:
    any of them
}