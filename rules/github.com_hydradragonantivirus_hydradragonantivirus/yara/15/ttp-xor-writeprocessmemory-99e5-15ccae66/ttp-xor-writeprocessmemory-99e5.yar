rule TTP_XOR_WriteProcessMemory_99e5 {
  strings:
    $key_99e5 = { ce 97 [2] fc b5 [2] fa 80 [2] d4 80 [2] eb 9c }

  condition:
    any of them
}