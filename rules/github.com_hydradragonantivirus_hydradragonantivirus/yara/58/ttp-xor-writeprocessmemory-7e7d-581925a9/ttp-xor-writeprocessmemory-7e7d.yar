rule TTP_XOR_WriteProcessMemory_7e7d {
  strings:
    $key_7e7d = { 29 0f [2] 1b 2d [2] 1d 18 [2] 33 18 [2] 0c 04 }

  condition:
    any of them
}