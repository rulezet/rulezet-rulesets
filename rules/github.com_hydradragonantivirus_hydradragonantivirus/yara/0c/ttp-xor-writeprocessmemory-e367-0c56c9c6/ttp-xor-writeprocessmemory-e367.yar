rule TTP_XOR_WriteProcessMemory_e367 {
  strings:
    $key_e367 = { b4 15 [2] 86 37 [2] 80 02 [2] ae 02 [2] 91 1e }

  condition:
    any of them
}