rule TTP_XOR_WriteProcessMemory_2a7f {
  strings:
    $key_2a7f = { 7d 0d [2] 4f 2f [2] 49 1a [2] 67 1a [2] 58 06 }

  condition:
    any of them
}