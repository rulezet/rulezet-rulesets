rule TTP_XOR_WriteProcessMemory_0651 {
  strings:
    $key_0651 = { 51 23 [2] 63 01 [2] 65 34 [2] 4b 34 [2] 74 28 }

  condition:
    any of them
}