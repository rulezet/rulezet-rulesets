rule TTP_XOR_WriteProcessMemory_c86f {
  strings:
    $key_c86f = { 9f 1d [2] ad 3f [2] ab 0a [2] 85 0a [2] ba 16 }

  condition:
    any of them
}