rule TTP_XOR_WriteProcessMemory_ea6f {
  strings:
    $key_ea6f = { bd 1d [2] 8f 3f [2] 89 0a [2] a7 0a [2] 98 16 }

  condition:
    any of them
}