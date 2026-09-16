rule TTP_XOR_WriteProcessMemory_7c4d {
  strings:
    $key_7c4d = { 2b 3f [2] 19 1d [2] 1f 28 [2] 31 28 [2] 0e 34 }

  condition:
    any of them
}