rule TTP_XOR_WriteProcessMemory_c81f {
  strings:
    $key_c81f = { 9f 6d [2] ad 4f [2] ab 7a [2] 85 7a [2] ba 66 }

  condition:
    any of them
}