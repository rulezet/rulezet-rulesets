rule TTP_XOR_WriteProcessMemory_6e5d {
  strings:
    $key_6e5d = { 39 2f [2] 0b 0d [2] 0d 38 [2] 23 38 [2] 1c 24 }

  condition:
    any of them
}