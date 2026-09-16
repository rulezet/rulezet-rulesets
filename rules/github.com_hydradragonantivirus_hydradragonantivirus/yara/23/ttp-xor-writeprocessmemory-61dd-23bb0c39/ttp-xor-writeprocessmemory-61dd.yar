rule TTP_XOR_WriteProcessMemory_61dd {
  strings:
    $key_61dd = { 36 af [2] 04 8d [2] 02 b8 [2] 2c b8 [2] 13 a4 }

  condition:
    any of them
}