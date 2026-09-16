rule TTP_XOR_WriteProcessMemory_180d {
  strings:
    $key_180d = { 4f 7f [2] 7d 5d [2] 7b 68 [2] 55 68 [2] 6a 74 }

  condition:
    any of them
}