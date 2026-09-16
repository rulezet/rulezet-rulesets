rule TTP_XOR_WriteProcessMemory_e352 {
  strings:
    $key_e352 = { b4 20 [2] 86 02 [2] 80 37 [2] ae 37 [2] 91 2b }

  condition:
    any of them
}