rule TTP_XOR_WriteProcessMemory_0414 {
  strings:
    $key_0414 = { 53 66 [2] 61 44 [2] 67 71 [2] 49 71 [2] 76 6d }

  condition:
    any of them
}