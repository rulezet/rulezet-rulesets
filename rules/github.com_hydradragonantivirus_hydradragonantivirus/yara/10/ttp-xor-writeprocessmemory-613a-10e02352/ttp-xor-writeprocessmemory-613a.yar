rule TTP_XOR_WriteProcessMemory_613a {
  strings:
    $key_613a = { 36 48 [2] 04 6a [2] 02 5f [2] 2c 5f [2] 13 43 }

  condition:
    any of them
}