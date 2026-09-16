rule TTP_XOR_WriteProcessMemory_4c5d {
  strings:
    $key_4c5d = { 1b 2f [2] 29 0d [2] 2f 38 [2] 01 38 [2] 3e 24 }

  condition:
    any of them
}