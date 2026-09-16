rule TTP_XOR_WriteProcessMemory_5d0d {
  strings:
    $key_5d0d = { 0a 7f [2] 38 5d [2] 3e 68 [2] 10 68 [2] 2f 74 }

  condition:
    any of them
}