rule TTP_XOR_WriteProcessMemory_7a1f {
  strings:
    $key_7a1f = { 2d 6d [2] 1f 4f [2] 19 7a [2] 37 7a [2] 08 66 }

  condition:
    any of them
}