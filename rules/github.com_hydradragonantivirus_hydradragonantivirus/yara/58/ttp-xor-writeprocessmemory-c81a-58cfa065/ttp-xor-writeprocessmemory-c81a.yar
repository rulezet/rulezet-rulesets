rule TTP_XOR_WriteProcessMemory_c81a {
  strings:
    $key_c81a = { 9f 68 [2] ad 4a [2] ab 7f [2] 85 7f [2] ba 63 }

  condition:
    any of them
}