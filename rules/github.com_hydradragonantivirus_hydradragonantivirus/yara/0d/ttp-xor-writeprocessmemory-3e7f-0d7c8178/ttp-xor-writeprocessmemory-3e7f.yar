rule TTP_XOR_WriteProcessMemory_3e7f {
  strings:
    $key_3e7f = { 69 0d [2] 5b 2f [2] 5d 1a [2] 73 1a [2] 4c 06 }

  condition:
    any of them
}