rule TTP_XOR_WriteProcessMemory_5203 {
  strings:
    $key_5203 = { 05 71 [2] 37 53 [2] 31 66 [2] 1f 66 [2] 20 7a }

  condition:
    any of them
}