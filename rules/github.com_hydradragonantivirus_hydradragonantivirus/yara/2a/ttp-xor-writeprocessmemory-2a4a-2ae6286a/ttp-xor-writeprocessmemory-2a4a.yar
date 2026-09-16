rule TTP_XOR_WriteProcessMemory_2a4a {
  strings:
    $key_2a4a = { 7d 38 [2] 4f 1a [2] 49 2f [2] 67 2f [2] 58 33 }

  condition:
    any of them
}