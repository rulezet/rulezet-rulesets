rule TTP_XOR_WriteProcessMemory_7a5c {
  strings:
    $key_7a5c = { 2d 2e [2] 1f 0c [2] 19 39 [2] 37 39 [2] 08 25 }

  condition:
    any of them
}