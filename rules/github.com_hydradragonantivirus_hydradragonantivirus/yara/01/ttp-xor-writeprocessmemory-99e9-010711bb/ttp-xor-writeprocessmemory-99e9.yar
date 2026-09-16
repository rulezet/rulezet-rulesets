rule TTP_XOR_WriteProcessMemory_99e9 {
  strings:
    $key_99e9 = { ce 9b [2] fc b9 [2] fa 8c [2] d4 8c [2] eb 90 }

  condition:
    any of them
}