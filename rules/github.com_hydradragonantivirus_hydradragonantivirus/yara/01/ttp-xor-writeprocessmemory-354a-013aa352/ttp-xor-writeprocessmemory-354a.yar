rule TTP_XOR_WriteProcessMemory_354a {
  strings:
    $key_354a = { 62 38 [2] 50 1a [2] 56 2f [2] 78 2f [2] 47 33 }

  condition:
    any of them
}