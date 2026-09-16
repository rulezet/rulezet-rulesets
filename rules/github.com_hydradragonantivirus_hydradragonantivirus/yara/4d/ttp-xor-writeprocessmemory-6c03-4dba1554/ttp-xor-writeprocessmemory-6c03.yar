rule TTP_XOR_WriteProcessMemory_6c03 {
  strings:
    $key_6c03 = { 3b 71 [2] 09 53 [2] 0f 66 [2] 21 66 [2] 1e 7a }

  condition:
    any of them
}