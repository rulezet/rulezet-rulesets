rule TTP_XOR_WriteProcessMemory_99e4 {
  strings:
    $key_99e4 = { ce 96 [2] fc b4 [2] fa 81 [2] d4 81 [2] eb 9d }

  condition:
    any of them
}