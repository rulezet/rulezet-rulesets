rule TTP_XOR_WriteProcessMemory_0467 {
  strings:
    $key_0467 = { 53 15 [2] 61 37 [2] 67 02 [2] 49 02 [2] 76 1e }

  condition:
    any of them
}