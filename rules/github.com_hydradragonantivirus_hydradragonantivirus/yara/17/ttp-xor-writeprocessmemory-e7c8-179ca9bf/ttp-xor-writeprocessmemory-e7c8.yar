rule TTP_XOR_WriteProcessMemory_e7c8 {
  strings:
    $key_e7c8 = { b0 ba [2] 82 98 [2] 84 ad [2] aa ad [2] 95 b1 }

  condition:
    any of them
}