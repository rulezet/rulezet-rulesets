rule TTP_XOR_WriteProcessMemory_99e3 {
  strings:
    $key_99e3 = { ce 91 [2] fc b3 [2] fa 86 [2] d4 86 [2] eb 9a }

  condition:
    any of them
}