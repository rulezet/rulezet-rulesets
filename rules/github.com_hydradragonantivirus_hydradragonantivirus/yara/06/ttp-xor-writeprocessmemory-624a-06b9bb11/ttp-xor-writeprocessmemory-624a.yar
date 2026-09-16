rule TTP_XOR_WriteProcessMemory_624a {
  strings:
    $key_624a = { 35 38 [2] 07 1a [2] 01 2f [2] 2f 2f [2] 10 33 }

  condition:
    any of them
}