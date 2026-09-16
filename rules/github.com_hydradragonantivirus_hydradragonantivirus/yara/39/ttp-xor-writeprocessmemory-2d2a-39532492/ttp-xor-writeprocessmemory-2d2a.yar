rule TTP_XOR_WriteProcessMemory_2d2a {
  strings:
    $key_2d2a = { 7a 58 [2] 48 7a [2] 4e 4f [2] 60 4f [2] 5f 53 }

  condition:
    any of them
}