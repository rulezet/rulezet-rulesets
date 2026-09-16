rule TTP_XOR_WriteProcessMemory_ea18 {
  strings:
    $key_ea18 = { bd 6a [2] 8f 48 [2] 89 7d [2] a7 7d [2] 98 61 }

  condition:
    any of them
}