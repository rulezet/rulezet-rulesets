rule TTP_XOR_WriteProcessMemory_227f {
  strings:
    $key_227f = { 75 0d [2] 47 2f [2] 41 1a [2] 6f 1a [2] 50 06 }

  condition:
    any of them
}