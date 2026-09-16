rule TTP_XOR_WriteProcessMemory_6f2a {
  strings:
    $key_6f2a = { 38 58 [2] 0a 7a [2] 0c 4f [2] 22 4f [2] 1d 53 }

  condition:
    any of them
}