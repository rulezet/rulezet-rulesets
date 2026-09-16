rule TTP_XOR_WriteProcessMemory_c84a {
  strings:
    $key_c84a = { 9f 38 [2] ad 1a [2] ab 2f [2] 85 2f [2] ba 33 }

  condition:
    any of them
}