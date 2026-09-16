rule TTP_XOR_WriteProcessMemory_0e7d {
  strings:
    $key_0e7d = { 59 0f [2] 6b 2d [2] 6d 18 [2] 43 18 [2] 7c 04 }

  condition:
    any of them
}