rule TTP_XOR_WriteProcessMemory_6b1f {
  strings:
    $key_6b1f = { 3c 6d [2] 0e 4f [2] 08 7a [2] 26 7a [2] 19 66 }

  condition:
    any of them
}