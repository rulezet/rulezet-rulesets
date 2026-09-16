rule TTP_XOR_WriteProcessMemory_4c52 {
  strings:
    $key_4c52 = { 1b 20 [2] 29 02 [2] 2f 37 [2] 01 37 [2] 3e 2b }

  condition:
    any of them
}