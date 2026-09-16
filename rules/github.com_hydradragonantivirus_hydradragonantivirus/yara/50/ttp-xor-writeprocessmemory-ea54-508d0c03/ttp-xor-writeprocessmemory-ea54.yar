rule TTP_XOR_WriteProcessMemory_ea54 {
  strings:
    $key_ea54 = { bd 26 [2] 8f 04 [2] 89 31 [2] a7 31 [2] 98 2d }

  condition:
    any of them
}