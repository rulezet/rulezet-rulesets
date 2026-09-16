rule TTP_XOR_WriteProcessMemory_244a {
  strings:
    $key_244a = { 73 38 [2] 41 1a [2] 47 2f [2] 69 2f [2] 56 33 }

  condition:
    any of them
}