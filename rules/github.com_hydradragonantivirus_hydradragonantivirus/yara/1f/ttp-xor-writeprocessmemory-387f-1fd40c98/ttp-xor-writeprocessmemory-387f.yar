rule TTP_XOR_WriteProcessMemory_387f {
  strings:
    $key_387f = { 6f 0d [2] 5d 2f [2] 5b 1a [2] 75 1a [2] 4a 06 }

  condition:
    any of them
}