rule TTP_XOR_WriteProcessMemory_480d {
  strings:
    $key_480d = { 1f 7f [2] 2d 5d [2] 2b 68 [2] 05 68 [2] 3a 74 }

  condition:
    any of them
}