rule TTP_XOR_WriteProcessMemory_0d5d {
  strings:
    $key_0d5d = { 5a 2f [2] 68 0d [2] 6e 38 [2] 40 38 [2] 7f 24 }

  condition:
    any of them
}