rule TTP_XOR_WriteProcessMemory_595d {
  strings:
    $key_595d = { 0e 2f [2] 3c 0d [2] 3a 38 [2] 14 38 [2] 2b 24 }

  condition:
    any of them
}