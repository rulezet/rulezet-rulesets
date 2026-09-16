rule TTP_XOR_WriteProcessMemory_6653 {
  strings:
    $key_6653 = { 31 21 [2] 03 03 [2] 05 36 [2] 2b 36 [2] 14 2a }

  condition:
    any of them
}