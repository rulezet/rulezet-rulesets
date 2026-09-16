rule TTP_XOR_WriteProcessMemory_7638 {
  strings:
    $key_7638 = { 21 4a [2] 13 68 [2] 15 5d [2] 3b 5d [2] 04 41 }

  condition:
    any of them
}