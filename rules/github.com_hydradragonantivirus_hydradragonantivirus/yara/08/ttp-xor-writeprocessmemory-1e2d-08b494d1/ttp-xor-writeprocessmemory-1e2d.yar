rule TTP_XOR_WriteProcessMemory_1e2d {
  strings:
    $key_1e2d = { 49 5f [2] 7b 7d [2] 7d 48 [2] 53 48 [2] 6c 54 }

  condition:
    any of them
}