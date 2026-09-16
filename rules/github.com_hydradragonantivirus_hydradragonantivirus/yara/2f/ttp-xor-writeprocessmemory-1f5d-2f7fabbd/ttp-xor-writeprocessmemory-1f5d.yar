rule TTP_XOR_WriteProcessMemory_1f5d {
  strings:
    $key_1f5d = { 48 2f [2] 7a 0d [2] 7c 38 [2] 52 38 [2] 6d 24 }

  condition:
    any of them
}