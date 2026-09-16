rule TTP_XOR_WriteProcessMemory_7e7a {
  strings:
    $key_7e7a = { 29 08 [2] 1b 2a [2] 1d 1f [2] 33 1f [2] 0c 03 }

  condition:
    any of them
}