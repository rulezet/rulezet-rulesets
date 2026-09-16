rule TTP_XOR_WriteProcessMemory_591a {
  strings:
    $key_591a = { 0e 68 [2] 3c 4a [2] 3a 7f [2] 14 7f [2] 2b 63 }

  condition:
    any of them
}