rule TTP_XOR_WriteProcessMemory_7e0d {
  strings:
    $key_7e0d = { 29 7f [2] 1b 5d [2] 1d 68 [2] 33 68 [2] 0c 74 }

  condition:
    any of them
}