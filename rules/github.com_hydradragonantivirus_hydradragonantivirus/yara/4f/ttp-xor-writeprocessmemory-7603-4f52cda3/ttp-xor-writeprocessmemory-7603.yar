rule TTP_XOR_WriteProcessMemory_7603 {
  strings:
    $key_7603 = { 21 71 [2] 13 53 [2] 15 66 [2] 3b 66 [2] 04 7a }

  condition:
    any of them
}