rule TTP_XOR_WriteProcessMemory_6231 {
  strings:
    $key_6231 = { 35 43 [2] 07 61 [2] 01 54 [2] 2f 54 [2] 10 48 }

  condition:
    any of them
}