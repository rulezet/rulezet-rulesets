rule TTP_XOR_WriteProcessMemory_721f {
  strings:
    $key_721f = { 25 6d [2] 17 4f [2] 11 7a [2] 3f 7a [2] 00 66 }

  condition:
    any of them
}