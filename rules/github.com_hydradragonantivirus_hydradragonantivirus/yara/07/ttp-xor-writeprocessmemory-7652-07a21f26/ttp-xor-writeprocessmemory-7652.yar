rule TTP_XOR_WriteProcessMemory_7652 {
  strings:
    $key_7652 = { 21 20 [2] 13 02 [2] 15 37 [2] 3b 37 [2] 04 2b }

  condition:
    any of them
}