rule TTP_XOR_WriteProcessMemory_6738 {
  strings:
    $key_6738 = { 30 4a [2] 02 68 [2] 04 5d [2] 2a 5d [2] 15 41 }

  condition:
    any of them
}