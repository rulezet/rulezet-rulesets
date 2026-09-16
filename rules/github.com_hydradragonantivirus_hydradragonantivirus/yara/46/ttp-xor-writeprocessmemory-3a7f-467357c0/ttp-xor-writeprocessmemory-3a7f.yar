rule TTP_XOR_WriteProcessMemory_3a7f {
  strings:
    $key_3a7f = { 6d 0d [2] 5f 2f [2] 59 1a [2] 77 1a [2] 48 06 }

  condition:
    any of them
}