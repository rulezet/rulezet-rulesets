rule TTP_XOR_WriteProcessMemory_190d {
  strings:
    $key_190d = { 4e 7f [2] 7c 5d [2] 7a 68 [2] 54 68 [2] 6b 74 }

  condition:
    any of them
}