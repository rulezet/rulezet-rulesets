rule TTP_XOR_WriteProcessMemory_0407 {
  strings:
    $key_0407 = { 53 75 [2] 61 57 [2] 67 62 [2] 49 62 [2] 76 7e }

  condition:
    any of them
}