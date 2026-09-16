rule TTP_XOR_WriteProcessMemory_1b2f {
  strings:
    $key_1b2f = { 4c 5d [2] 7e 7f [2] 78 4a [2] 56 4a [2] 69 56 }

  condition:
    any of them
}