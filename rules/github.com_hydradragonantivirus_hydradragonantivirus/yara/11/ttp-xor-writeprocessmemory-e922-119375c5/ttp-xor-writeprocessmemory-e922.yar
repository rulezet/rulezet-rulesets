rule TTP_XOR_WriteProcessMemory_e922 {
  strings:
    $key_e922 = { be 50 [2] 8c 72 [2] 8a 47 [2] a4 47 [2] 9b 5b }

  condition:
    any of them
}