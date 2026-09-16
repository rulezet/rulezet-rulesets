rule TTP_XOR_WriteProcessMemory_2c7f {
  strings:
    $key_2c7f = { 7b 0d [2] 49 2f [2] 4f 1a [2] 61 1a [2] 5e 06 }

  condition:
    any of them
}