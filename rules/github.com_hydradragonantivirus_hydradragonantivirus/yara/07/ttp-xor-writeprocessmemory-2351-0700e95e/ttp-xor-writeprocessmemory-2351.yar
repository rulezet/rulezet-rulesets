rule TTP_XOR_WriteProcessMemory_2351 {
  strings:
    $key_2351 = { 74 23 [2] 46 01 [2] 40 34 [2] 6e 34 [2] 51 28 }

  condition:
    any of them
}