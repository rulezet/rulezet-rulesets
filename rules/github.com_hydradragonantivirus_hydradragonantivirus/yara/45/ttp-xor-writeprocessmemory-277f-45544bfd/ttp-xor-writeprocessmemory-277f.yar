rule TTP_XOR_WriteProcessMemory_277f {
  strings:
    $key_277f = { 70 0d [2] 42 2f [2] 44 1a [2] 6a 1a [2] 55 06 }

  condition:
    any of them
}