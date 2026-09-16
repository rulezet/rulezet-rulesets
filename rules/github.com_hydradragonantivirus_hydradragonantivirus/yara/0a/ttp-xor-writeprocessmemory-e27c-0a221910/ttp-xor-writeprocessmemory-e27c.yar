rule TTP_XOR_WriteProcessMemory_e27c {
  strings:
    $key_e27c = { b5 0e [2] 87 2c [2] 81 19 [2] af 19 [2] 90 05 }

  condition:
    any of them
}