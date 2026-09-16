rule TTP_XOR_WriteProcessMemory_0ec8 {
  strings:
    $key_0ec8 = { 59 ba [2] 6b 98 [2] 6d ad [2] 43 ad [2] 7c b1 }

  condition:
    any of them
}