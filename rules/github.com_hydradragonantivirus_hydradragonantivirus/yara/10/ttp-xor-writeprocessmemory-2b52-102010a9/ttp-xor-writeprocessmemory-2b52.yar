rule TTP_XOR_WriteProcessMemory_2b52 {
  strings:
    $key_2b52 = { 7c 20 [2] 4e 02 [2] 48 37 [2] 66 37 [2] 59 2b }

  condition:
    any of them
}