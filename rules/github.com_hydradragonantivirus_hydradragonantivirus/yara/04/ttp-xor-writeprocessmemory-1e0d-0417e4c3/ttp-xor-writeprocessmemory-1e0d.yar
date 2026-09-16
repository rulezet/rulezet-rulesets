rule TTP_XOR_WriteProcessMemory_1e0d {
  strings:
    $key_1e0d = { 49 7f [2] 7b 5d [2] 7d 68 [2] 53 68 [2] 6c 74 }

  condition:
    any of them
}