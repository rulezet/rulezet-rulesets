rule TTP_XOR_WriteProcessMemory_2d1a {
  strings:
    $key_2d1a = { 7a 68 [2] 48 4a [2] 4e 7f [2] 60 7f [2] 5f 63 }

  condition:
    any of them
}