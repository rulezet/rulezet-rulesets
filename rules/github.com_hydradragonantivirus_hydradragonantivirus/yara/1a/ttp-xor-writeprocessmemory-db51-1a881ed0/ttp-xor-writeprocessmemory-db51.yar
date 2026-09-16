rule TTP_XOR_WriteProcessMemory_db51 {
  strings:
    $key_db51 = { 8c 23 [2] be 01 [2] b8 34 [2] 96 34 [2] a9 28 }

  condition:
    any of them
}