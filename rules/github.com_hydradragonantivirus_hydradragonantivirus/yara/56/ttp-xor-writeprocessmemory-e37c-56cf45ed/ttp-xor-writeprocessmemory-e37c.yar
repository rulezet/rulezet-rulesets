rule TTP_XOR_WriteProcessMemory_e37c {
  strings:
    $key_e37c = { b4 0e [2] 86 2c [2] 80 19 [2] ae 19 [2] 91 05 }

  condition:
    any of them
}