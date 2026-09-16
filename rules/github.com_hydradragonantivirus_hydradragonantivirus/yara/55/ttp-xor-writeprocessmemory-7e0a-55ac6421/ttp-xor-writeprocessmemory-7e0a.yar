rule TTP_XOR_WriteProcessMemory_7e0a {
  strings:
    $key_7e0a = { 29 78 [2] 1b 5a [2] 1d 6f [2] 33 6f [2] 0c 73 }

  condition:
    any of them
}