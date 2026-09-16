rule TTP_XOR_WriteProcessMemory_7952 {
  strings:
    $key_7952 = { 2e 20 [2] 1c 02 [2] 1a 37 [2] 34 37 [2] 0b 2b }

  condition:
    any of them
}