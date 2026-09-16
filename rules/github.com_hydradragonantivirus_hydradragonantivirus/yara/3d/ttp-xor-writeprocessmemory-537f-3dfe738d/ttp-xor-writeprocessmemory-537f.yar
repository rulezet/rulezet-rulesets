rule TTP_XOR_WriteProcessMemory_537f {
  strings:
    $key_537f = { 04 0d [2] 36 2f [2] 30 1a [2] 1e 1a [2] 21 06 }

  condition:
    any of them
}