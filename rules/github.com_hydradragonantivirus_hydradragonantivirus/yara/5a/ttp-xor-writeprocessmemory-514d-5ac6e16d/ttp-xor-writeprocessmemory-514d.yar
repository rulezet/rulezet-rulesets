rule TTP_XOR_WriteProcessMemory_514d {
  strings:
    $key_514d = { 06 3f [2] 34 1d [2] 32 28 [2] 1c 28 [2] 23 34 }

  condition:
    any of them
}