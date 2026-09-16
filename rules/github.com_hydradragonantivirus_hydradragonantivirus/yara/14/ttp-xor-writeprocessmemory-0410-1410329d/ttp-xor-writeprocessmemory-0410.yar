rule TTP_XOR_WriteProcessMemory_0410 {
  strings:
    $key_0410 = { 53 62 [2] 61 40 [2] 67 75 [2] 49 75 [2] 76 69 }

  condition:
    any of them
}