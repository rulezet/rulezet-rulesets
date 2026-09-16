rule TTP_XOR_WriteProcessMemory_c85f {
  strings:
    $key_c85f = { 9f 2d [2] ad 0f [2] ab 3a [2] 85 3a [2] ba 26 }

  condition:
    any of them
}