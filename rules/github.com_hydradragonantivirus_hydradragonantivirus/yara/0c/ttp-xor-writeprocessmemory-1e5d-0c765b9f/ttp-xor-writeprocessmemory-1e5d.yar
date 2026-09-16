rule TTP_XOR_WriteProcessMemory_1e5d {
  strings:
    $key_1e5d = { 49 2f [2] 7b 0d [2] 7d 38 [2] 53 38 [2] 6c 24 }

  condition:
    any of them
}