rule TTP_XOR_WriteProcessMemory_0c4d {
  strings:
    $key_0c4d = { 5b 3f [2] 69 1d [2] 6f 28 [2] 41 28 [2] 7e 34 }

  condition:
    any of them
}