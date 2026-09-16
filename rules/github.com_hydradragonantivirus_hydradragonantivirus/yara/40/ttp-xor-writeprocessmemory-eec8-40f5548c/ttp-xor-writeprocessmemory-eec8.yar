rule TTP_XOR_WriteProcessMemory_eec8 {
  strings:
    $key_eec8 = { b9 ba [2] 8b 98 [2] 8d ad [2] a3 ad [2] 9c b1 }

  condition:
    any of them
}