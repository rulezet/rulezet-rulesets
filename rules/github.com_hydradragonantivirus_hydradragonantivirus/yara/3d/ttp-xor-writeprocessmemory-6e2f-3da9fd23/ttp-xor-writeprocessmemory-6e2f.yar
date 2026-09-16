rule TTP_XOR_WriteProcessMemory_6e2f {
  strings:
    $key_6e2f = { 39 5d [2] 0b 7f [2] 0d 4a [2] 23 4a [2] 1c 56 }

  condition:
    any of them
}