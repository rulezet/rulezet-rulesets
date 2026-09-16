rule TTP_XOR_WriteProcessMemory_2e7f {
  strings:
    $key_2e7f = { 79 0d [2] 4b 2f [2] 4d 1a [2] 63 1a [2] 5c 06 }

  condition:
    any of them
}