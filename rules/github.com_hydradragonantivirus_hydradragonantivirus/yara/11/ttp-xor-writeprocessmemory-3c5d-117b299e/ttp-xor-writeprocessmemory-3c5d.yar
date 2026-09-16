rule TTP_XOR_WriteProcessMemory_3c5d {
  strings:
    $key_3c5d = { 6b 2f [2] 59 0d [2] 5f 38 [2] 71 38 [2] 4e 24 }

  condition:
    any of them
}