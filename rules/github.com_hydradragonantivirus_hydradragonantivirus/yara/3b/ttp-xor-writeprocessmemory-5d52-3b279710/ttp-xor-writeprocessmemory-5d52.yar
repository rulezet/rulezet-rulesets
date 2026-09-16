rule TTP_XOR_WriteProcessMemory_5d52 {
  strings:
    $key_5d52 = { 0a 20 [2] 38 02 [2] 3e 37 [2] 10 37 [2] 2f 2b }

  condition:
    any of them
}