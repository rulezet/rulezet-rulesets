rule TTP_XOR_WriteProcessMemory_11dd {
  strings:
    $key_11dd = { 46 af [2] 74 8d [2] 72 b8 [2] 5c b8 [2] 63 a4 }

  condition:
    any of them
}