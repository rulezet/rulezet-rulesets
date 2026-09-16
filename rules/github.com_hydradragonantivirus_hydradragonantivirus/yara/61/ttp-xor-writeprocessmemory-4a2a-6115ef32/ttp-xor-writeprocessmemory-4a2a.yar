rule TTP_XOR_WriteProcessMemory_4a2a {
  strings:
    $key_4a2a = { 1d 58 [2] 2f 7a [2] 29 4f [2] 07 4f [2] 38 53 }

  condition:
    any of them
}