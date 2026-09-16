rule TTP_XOR_WriteProcessMemory_e523 {
  strings:
    $key_e523 = { b2 51 [2] 80 73 [2] 86 46 [2] a8 46 [2] 97 5a }

  condition:
    any of them
}