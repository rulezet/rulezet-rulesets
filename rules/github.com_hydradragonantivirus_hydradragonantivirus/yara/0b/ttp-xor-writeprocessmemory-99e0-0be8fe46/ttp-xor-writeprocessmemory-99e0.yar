rule TTP_XOR_WriteProcessMemory_99e0 {
  strings:
    $key_99e0 = { ce 92 [2] fc b0 [2] fa 85 [2] d4 85 [2] eb 99 }

  condition:
    any of them
}