rule TTP_XOR_WriteProcessMemory_686f {
  strings:
    $key_686f = { 3f 1d [2] 0d 3f [2] 0b 0a [2] 25 0a [2] 1a 16 }

  condition:
    any of them
}