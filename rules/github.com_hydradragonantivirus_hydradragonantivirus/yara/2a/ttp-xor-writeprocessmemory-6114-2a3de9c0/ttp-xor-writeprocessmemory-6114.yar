rule TTP_XOR_WriteProcessMemory_6114 {
  strings:
    $key_6114 = { 36 66 [2] 04 44 [2] 02 71 [2] 2c 71 [2] 13 6d }

  condition:
    any of them
}