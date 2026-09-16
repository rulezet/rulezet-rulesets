rule TTP_XOR_WriteProcessMemory_ea7f {
  strings:
    $key_ea7f = { bd 0d [2] 8f 2f [2] 89 1a [2] a7 1a [2] 98 06 }

  condition:
    any of them
}