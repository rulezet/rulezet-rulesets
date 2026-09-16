rule TTP_XOR_WriteProcessMemory_0e5d {
  strings:
    $key_0e5d = { 59 2f [2] 6b 0d [2] 6d 38 [2] 43 38 [2] 7c 24 }

  condition:
    any of them
}