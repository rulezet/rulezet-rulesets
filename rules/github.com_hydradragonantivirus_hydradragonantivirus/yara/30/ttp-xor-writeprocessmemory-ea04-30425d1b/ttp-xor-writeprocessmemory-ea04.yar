rule TTP_XOR_WriteProcessMemory_ea04 {
  strings:
    $key_ea04 = { bd 76 [2] 8f 54 [2] 89 61 [2] a7 61 [2] 98 7d }

  condition:
    any of them
}