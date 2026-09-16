rule TTP_XOR_WriteProcessMemory_4e6c {
  strings:
    $key_4e6c = { 19 1e [2] 2b 3c [2] 2d 09 [2] 03 09 [2] 3c 15 }

  condition:
    any of them
}