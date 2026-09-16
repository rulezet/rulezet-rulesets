rule TTP_XOR_WriteProcessMemory_0a4d {
  strings:
    $key_0a4d = { 5d 3f [2] 6f 1d [2] 69 28 [2] 47 28 [2] 78 34 }

  condition:
    any of them
}