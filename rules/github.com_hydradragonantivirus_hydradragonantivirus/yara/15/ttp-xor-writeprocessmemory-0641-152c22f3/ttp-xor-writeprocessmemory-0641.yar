rule TTP_XOR_WriteProcessMemory_0641 {
  strings:
    $key_0641 = { 51 33 [2] 63 11 [2] 65 24 [2] 4b 24 [2] 74 38 }

  condition:
    any of them
}