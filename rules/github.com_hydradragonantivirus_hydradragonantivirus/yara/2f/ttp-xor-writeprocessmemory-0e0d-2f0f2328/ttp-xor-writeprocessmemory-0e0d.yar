rule TTP_XOR_WriteProcessMemory_0e0d {
  strings:
    $key_0e0d = { 59 7f [2] 6b 5d [2] 6d 68 [2] 43 68 [2] 7c 74 }

  condition:
    any of them
}