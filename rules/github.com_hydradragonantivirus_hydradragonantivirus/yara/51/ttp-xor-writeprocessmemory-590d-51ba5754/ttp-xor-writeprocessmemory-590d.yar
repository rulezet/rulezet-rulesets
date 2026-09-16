rule TTP_XOR_WriteProcessMemory_590d {
  strings:
    $key_590d = { 0e 7f [2] 3c 5d [2] 3a 68 [2] 14 68 [2] 2b 74 }

  condition:
    any of them
}