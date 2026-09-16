rule TTP_XOR_WriteProcessMemory_780d {
  strings:
    $key_780d = { 2f 7f [2] 1d 5d [2] 1b 68 [2] 35 68 [2] 0a 74 }

  condition:
    any of them
}