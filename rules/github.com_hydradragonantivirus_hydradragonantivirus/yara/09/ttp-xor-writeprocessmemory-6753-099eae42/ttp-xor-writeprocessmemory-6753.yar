rule TTP_XOR_WriteProcessMemory_6753 {
  strings:
    $key_6753 = { 30 21 [2] 02 03 [2] 04 36 [2] 2a 36 [2] 15 2a }

  condition:
    any of them
}