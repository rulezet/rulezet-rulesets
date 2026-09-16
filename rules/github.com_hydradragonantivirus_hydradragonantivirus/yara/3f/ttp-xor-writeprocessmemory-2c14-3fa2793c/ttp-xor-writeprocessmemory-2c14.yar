rule TTP_XOR_WriteProcessMemory_2c14 {
  strings:
    $key_2c14 = { 7b 66 [2] 49 44 [2] 4f 71 [2] 61 71 [2] 5e 6d }

  condition:
    any of them
}