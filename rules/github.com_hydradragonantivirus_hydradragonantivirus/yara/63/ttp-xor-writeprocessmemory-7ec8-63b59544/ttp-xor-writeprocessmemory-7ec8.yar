rule TTP_XOR_WriteProcessMemory_7ec8 {
  strings:
    $key_7ec8 = { 29 ba [2] 1b 98 [2] 1d ad [2] 33 ad [2] 0c b1 }

  condition:
    any of them
}