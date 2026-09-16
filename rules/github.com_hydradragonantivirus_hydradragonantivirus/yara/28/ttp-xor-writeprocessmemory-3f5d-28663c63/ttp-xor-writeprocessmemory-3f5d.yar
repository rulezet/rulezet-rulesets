rule TTP_XOR_WriteProcessMemory_3f5d {
  strings:
    $key_3f5d = { 68 2f [2] 5a 0d [2] 5c 38 [2] 72 38 [2] 4d 24 }

  condition:
    any of them
}