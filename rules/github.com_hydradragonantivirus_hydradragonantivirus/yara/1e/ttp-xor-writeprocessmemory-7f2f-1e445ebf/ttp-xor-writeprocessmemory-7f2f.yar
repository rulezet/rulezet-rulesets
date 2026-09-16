rule TTP_XOR_WriteProcessMemory_7f2f {
  strings:
    $key_7f2f = { 28 5d [2] 1a 7f [2] 1c 4a [2] 32 4a [2] 0d 56 }

  condition:
    any of them
}