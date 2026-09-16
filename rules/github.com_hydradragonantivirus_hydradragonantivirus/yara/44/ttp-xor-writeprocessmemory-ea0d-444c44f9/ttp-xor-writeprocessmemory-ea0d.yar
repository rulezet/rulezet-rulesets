rule TTP_XOR_WriteProcessMemory_ea0d {
  strings:
    $key_ea0d = { bd 7f [2] 8f 5d [2] 89 68 [2] a7 68 [2] 98 74 }

  condition:
    any of them
}