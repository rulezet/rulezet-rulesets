rule TTP_XOR_WriteProcessMemory_3ec8 {
  strings:
    $key_3ec8 = { 69 ba [2] 5b 98 [2] 5d ad [2] 73 ad [2] 4c b1 }

  condition:
    any of them
}