rule TTP_XOR_WriteProcessMemory_ec20 {
  strings:
    $key_ec20 = { bb 52 [2] 89 70 [2] 8f 45 [2] a1 45 [2] 9e 59 }

  condition:
    any of them
}