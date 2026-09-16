rule TTP_XOR_WriteProcessMemory_0838 {
  strings:
    $key_0838 = { 5f 4a [2] 6d 68 [2] 6b 5d [2] 45 5d [2] 7a 41 }

  condition:
    any of them
}