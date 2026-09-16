rule TTP_XOR_WriteProcessMemory_6b2f {
  strings:
    $key_6b2f = { 3c 5d [2] 0e 7f [2] 08 4a [2] 26 4a [2] 19 56 }

  condition:
    any of them
}