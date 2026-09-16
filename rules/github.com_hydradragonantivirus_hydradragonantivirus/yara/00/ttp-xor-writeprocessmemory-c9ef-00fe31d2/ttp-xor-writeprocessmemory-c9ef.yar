rule TTP_XOR_WriteProcessMemory_c9ef {
  strings:
    $key_c9ef = { 9e 9d [2] ac bf [2] aa 8a [2] 84 8a [2] bb 96 }

  condition:
    any of them
}