rule TTP_XOR_WriteProcessMemory_6270 {
  strings:
    $key_6270 = { 35 02 [2] 07 20 [2] 01 15 [2] 2f 15 [2] 10 09 }

  condition:
    any of them
}