rule TTP_XOR_WriteProcessMemory_99f2 {
  strings:
    $key_99f2 = { ce 80 [2] fc a2 [2] fa 97 [2] d4 97 [2] eb 8b }

  condition:
    any of them
}