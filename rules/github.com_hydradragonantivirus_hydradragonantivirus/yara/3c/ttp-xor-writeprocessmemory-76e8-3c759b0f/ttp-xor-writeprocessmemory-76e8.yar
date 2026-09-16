rule TTP_XOR_WriteProcessMemory_76e8 {
  strings:
    $key_76e8 = { 21 9a [2] 13 b8 [2] 15 8d [2] 3b 8d [2] 04 91 }

  condition:
    any of them
}