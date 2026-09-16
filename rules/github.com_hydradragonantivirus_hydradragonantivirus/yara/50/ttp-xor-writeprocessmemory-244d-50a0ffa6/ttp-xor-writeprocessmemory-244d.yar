rule TTP_XOR_WriteProcessMemory_244d {
  strings:
    $key_244d = { 73 3f [2] 41 1d [2] 47 28 [2] 69 28 [2] 56 34 }

  condition:
    any of them
}