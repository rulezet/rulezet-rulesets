rule TTP_XOR_WriteProcessMemory_614a {
  strings:
    $key_614a = { 36 38 [2] 04 1a [2] 02 2f [2] 2c 2f [2] 13 33 }

  condition:
    any of them
}