rule TTP_XOR_WriteProcessMemory_641a {
  strings:
    $key_641a = { 33 68 [2] 01 4a [2] 07 7f [2] 29 7f [2] 16 63 }

  condition:
    any of them
}