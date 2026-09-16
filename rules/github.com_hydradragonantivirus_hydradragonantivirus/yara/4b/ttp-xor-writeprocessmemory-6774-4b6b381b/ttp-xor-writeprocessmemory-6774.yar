rule TTP_XOR_WriteProcessMemory_6774 {
  strings:
    $key_6774 = { 30 06 [2] 02 24 [2] 04 11 [2] 2a 11 [2] 15 0d }

  condition:
    any of them
}