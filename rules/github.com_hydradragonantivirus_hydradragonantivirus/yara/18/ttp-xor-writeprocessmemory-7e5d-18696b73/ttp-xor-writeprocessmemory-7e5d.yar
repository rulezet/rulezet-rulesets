rule TTP_XOR_WriteProcessMemory_7e5d {
  strings:
    $key_7e5d = { 29 2f [2] 1b 0d [2] 1d 38 [2] 33 38 [2] 0c 24 }

  condition:
    any of them
}