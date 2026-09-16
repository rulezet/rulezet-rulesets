rule TTP_XOR_WriteProcessMemory_6241 {
  strings:
    $key_6241 = { 35 33 [2] 07 11 [2] 01 24 [2] 2f 24 [2] 10 38 }

  condition:
    any of them
}