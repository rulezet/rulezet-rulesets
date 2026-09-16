rule TTP_XOR_WriteProcessMemory_e349 {
  strings:
    $key_e349 = { b4 3b [2] 86 19 [2] 80 2c [2] ae 2c [2] 91 30 }

  condition:
    any of them
}