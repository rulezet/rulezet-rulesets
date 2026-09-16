rule TTP_XOR_WriteProcessMemory_1c14 {
  strings:
    $key_1c14 = { 4b 66 [2] 79 44 [2] 7f 71 [2] 51 71 [2] 6e 6d }

  condition:
    any of them
}