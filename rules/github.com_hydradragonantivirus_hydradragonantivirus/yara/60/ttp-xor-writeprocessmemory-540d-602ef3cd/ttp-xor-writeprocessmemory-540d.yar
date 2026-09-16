rule TTP_XOR_WriteProcessMemory_540d {
  strings:
    $key_540d = { 03 7f [2] 31 5d [2] 37 68 [2] 19 68 [2] 26 74 }

  condition:
    any of them
}