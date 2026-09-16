rule TTP_XOR_WriteProcessMemory_637f {
  strings:
    $key_637f = { 34 0d [2] 06 2f [2] 00 1a [2] 2e 1a [2] 11 06 }

  condition:
    any of them
}