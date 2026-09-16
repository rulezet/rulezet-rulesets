rule TTP_XOR_WriteProcessMemory_ec30 {
  strings:
    $key_ec30 = { bb 42 [2] 89 60 [2] 8f 55 [2] a1 55 [2] 9e 49 }

  condition:
    any of them
}