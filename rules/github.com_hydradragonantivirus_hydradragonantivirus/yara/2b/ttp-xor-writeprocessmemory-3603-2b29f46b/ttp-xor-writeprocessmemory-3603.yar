rule TTP_XOR_WriteProcessMemory_3603 {
  strings:
    $key_3603 = { 61 71 [2] 53 53 [2] 55 66 [2] 7b 66 [2] 44 7a }

  condition:
    any of them
}