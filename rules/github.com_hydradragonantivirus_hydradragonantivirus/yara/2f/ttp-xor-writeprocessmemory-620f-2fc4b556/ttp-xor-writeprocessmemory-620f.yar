rule TTP_XOR_WriteProcessMemory_620f {
  strings:
    $key_620f = { 35 7d [2] 07 5f [2] 01 6a [2] 2f 6a [2] 10 76 }

  condition:
    any of them
}