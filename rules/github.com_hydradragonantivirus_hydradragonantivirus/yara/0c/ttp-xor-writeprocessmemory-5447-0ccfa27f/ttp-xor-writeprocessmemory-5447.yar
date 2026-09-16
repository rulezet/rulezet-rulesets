rule TTP_XOR_WriteProcessMemory_5447 {
  strings:
    $key_5447 = { 03 35 [2] 31 17 [2] 37 22 [2] 19 22 [2] 26 3e }

  condition:
    any of them
}