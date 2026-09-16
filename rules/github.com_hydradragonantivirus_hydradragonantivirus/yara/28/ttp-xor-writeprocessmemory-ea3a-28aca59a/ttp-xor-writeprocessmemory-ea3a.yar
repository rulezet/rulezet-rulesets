rule TTP_XOR_WriteProcessMemory_ea3a {
  strings:
    $key_ea3a = { bd 48 [2] 8f 6a [2] 89 5f [2] a7 5f [2] 98 43 }

  condition:
    any of them
}