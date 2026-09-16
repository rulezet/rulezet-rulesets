rule TTP_XOR_WriteProcessMemory_ea4a {
  strings:
    $key_ea4a = { bd 38 [2] 8f 1a [2] 89 2f [2] a7 2f [2] 98 33 }

  condition:
    any of them
}