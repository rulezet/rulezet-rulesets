rule TTP_XOR_WriteProcessMemory_497f {
  strings:
    $key_497f = { 1e 0d [2] 2c 2f [2] 2a 1a [2] 04 1a [2] 3b 06 }

  condition:
    any of them
}