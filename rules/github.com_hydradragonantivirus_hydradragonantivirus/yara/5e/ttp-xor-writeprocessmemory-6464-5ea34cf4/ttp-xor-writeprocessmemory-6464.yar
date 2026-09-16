rule TTP_XOR_WriteProcessMemory_6464 {
  strings:
    $key_6464 = { 33 16 [2] 01 34 [2] 07 01 [2] 29 01 [2] 16 1d }

  condition:
    any of them
}