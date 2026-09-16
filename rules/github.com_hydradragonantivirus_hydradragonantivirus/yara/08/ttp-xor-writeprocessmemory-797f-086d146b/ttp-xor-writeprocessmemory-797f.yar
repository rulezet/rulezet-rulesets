rule TTP_XOR_WriteProcessMemory_797f {
  strings:
    $key_797f = { 2e 0d [2] 1c 2f [2] 1a 1a [2] 34 1a [2] 0b 06 }

  condition:
    any of them
}