rule TTP_XOR_WriteProcessMemory_ea4d {
  strings:
    $key_ea4d = { bd 3f [2] 8f 1d [2] 89 28 [2] a7 28 [2] 98 34 }

  condition:
    any of them
}