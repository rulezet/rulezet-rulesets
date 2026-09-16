rule TTP_XOR_WriteProcessMemory_0c5d {
  strings:
    $key_0c5d = { 5b 2f [2] 69 0d [2] 6f 38 [2] 41 38 [2] 7e 24 }

  condition:
    any of them
}