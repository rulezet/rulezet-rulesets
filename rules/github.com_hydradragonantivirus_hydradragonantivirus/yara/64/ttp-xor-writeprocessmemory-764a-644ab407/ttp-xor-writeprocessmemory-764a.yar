rule TTP_XOR_WriteProcessMemory_764a {
  strings:
    $key_764a = { 21 38 [2] 13 1a [2] 15 2f [2] 3b 2f [2] 04 33 }

  condition:
    any of them
}