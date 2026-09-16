rule TTP_XOR_WriteProcessMemory_6218 {
  strings:
    $key_6218 = { 35 6a [2] 07 48 [2] 01 7d [2] 2f 7d [2] 10 61 }

  condition:
    any of them
}