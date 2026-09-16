rule TTP_XOR_WriteProcessMemory_1c2f {
  strings:
    $key_1c2f = { 4b 5d [2] 79 7f [2] 7f 4a [2] 51 4a [2] 6e 56 }

  condition:
    any of them
}