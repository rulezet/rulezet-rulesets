rule TTP_XOR_WriteProcessMemory_99e1 {
  strings:
    $key_99e1 = { ce 93 [2] fc b1 [2] fa 84 [2] d4 84 [2] eb 98 }

  condition:
    any of them
}