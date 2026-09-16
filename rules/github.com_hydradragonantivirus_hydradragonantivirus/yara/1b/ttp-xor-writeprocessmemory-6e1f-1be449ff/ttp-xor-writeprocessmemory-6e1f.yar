rule TTP_XOR_WriteProcessMemory_6e1f {
  strings:
    $key_6e1f = { 39 6d [2] 0b 4f [2] 0d 7a [2] 23 7a [2] 1c 66 }

  condition:
    any of them
}