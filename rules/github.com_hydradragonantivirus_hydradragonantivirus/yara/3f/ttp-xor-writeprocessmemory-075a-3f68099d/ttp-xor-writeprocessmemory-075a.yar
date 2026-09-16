rule TTP_XOR_WriteProcessMemory_075a {
  strings:
    $key_075a = { 50 28 [2] 62 0a [2] 64 3f [2] 4a 3f [2] 75 23 }

  condition:
    any of them
}