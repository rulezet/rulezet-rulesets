rule TTP_XOR_WriteProcessMemory_e355 {
  strings:
    $key_e355 = { b4 27 [2] 86 05 [2] 80 30 [2] ae 30 [2] 91 2c }

  condition:
    any of them
}