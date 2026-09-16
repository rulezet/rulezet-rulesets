rule TTP_XOR_WriteProcessMemory_2f4a {
  strings:
    $key_2f4a = { 78 38 [2] 4a 1a [2] 4c 2f [2] 62 2f [2] 5d 33 }

  condition:
    any of them
}