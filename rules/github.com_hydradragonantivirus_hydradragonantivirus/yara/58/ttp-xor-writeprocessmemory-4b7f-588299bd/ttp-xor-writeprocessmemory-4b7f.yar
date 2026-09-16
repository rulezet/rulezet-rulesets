rule TTP_XOR_WriteProcessMemory_4b7f {
  strings:
    $key_4b7f = { 1c 0d [2] 2e 2f [2] 28 1a [2] 06 1a [2] 39 06 }

  condition:
    any of them
}