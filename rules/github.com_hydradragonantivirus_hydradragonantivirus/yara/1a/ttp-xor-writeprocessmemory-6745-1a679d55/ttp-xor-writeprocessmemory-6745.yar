rule TTP_XOR_WriteProcessMemory_6745 {
  strings:
    $key_6745 = { 30 37 [2] 02 15 [2] 04 20 [2] 2a 20 [2] 15 3c }

  condition:
    any of them
}