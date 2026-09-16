rule TTP_XOR_WriteProcessMemory_002f {
  strings:
    $key_002f = { 57 5d [2] 65 7f [2] 63 4a [2] 4d 4a [2] 72 56 }

  condition:
    any of them
}