rule TTP_XOR_WriteProcessMemory_7ab9 {
  strings:
    $key_7ab9 = { 2d cb [2] 1f e9 [2] 19 dc [2] 37 dc [2] 08 c0 }

  condition:
    any of them
}