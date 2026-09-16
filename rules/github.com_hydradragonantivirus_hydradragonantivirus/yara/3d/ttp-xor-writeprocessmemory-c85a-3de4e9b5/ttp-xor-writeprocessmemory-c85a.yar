rule TTP_XOR_WriteProcessMemory_c85a {
  strings:
    $key_c85a = { 9f 28 [2] ad 0a [2] ab 3f [2] 85 3f [2] ba 23 }

  condition:
    any of them
}