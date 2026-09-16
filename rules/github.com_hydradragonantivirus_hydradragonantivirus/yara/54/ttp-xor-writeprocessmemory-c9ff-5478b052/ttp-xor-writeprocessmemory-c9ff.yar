rule TTP_XOR_WriteProcessMemory_c9ff {
  strings:
    $key_c9ff = { 9e 8d [2] ac af [2] aa 9a [2] 84 9a [2] bb 86 }

  condition:
    any of them
}