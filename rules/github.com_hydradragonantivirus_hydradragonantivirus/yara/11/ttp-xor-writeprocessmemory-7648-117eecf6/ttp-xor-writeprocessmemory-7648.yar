rule TTP_XOR_WriteProcessMemory_7648 {
  strings:
    $key_7648 = { 21 3a [2] 13 18 [2] 15 2d [2] 3b 2d [2] 04 31 }

  condition:
    any of them
}