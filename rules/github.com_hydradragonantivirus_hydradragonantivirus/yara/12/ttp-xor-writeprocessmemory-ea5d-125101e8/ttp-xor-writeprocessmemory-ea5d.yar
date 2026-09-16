rule TTP_XOR_WriteProcessMemory_ea5d {
  strings:
    $key_ea5d = { bd 2f [2] 8f 0d [2] 89 38 [2] a7 38 [2] 98 24 }

  condition:
    any of them
}