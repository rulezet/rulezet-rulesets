rule TTP_XOR_WriteProcessMemory_3c14 {
  strings:
    $key_3c14 = { 6b 66 [2] 59 44 [2] 5f 71 [2] 71 71 [2] 4e 6d }

  condition:
    any of them
}