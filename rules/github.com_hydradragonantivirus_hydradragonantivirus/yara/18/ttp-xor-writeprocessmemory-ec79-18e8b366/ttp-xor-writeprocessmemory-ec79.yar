rule TTP_XOR_WriteProcessMemory_ec79 {
  strings:
    $key_ec79 = { bb 0b [2] 89 29 [2] 8f 1c [2] a1 1c [2] 9e 00 }

  condition:
    any of them
}