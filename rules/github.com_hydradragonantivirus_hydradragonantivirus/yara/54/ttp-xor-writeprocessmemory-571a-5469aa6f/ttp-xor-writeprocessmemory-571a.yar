rule TTP_XOR_WriteProcessMemory_571a {
  strings:
    $key_571a = { 00 68 [2] 32 4a [2] 34 7f [2] 1a 7f [2] 25 63 }

  condition:
    any of them
}