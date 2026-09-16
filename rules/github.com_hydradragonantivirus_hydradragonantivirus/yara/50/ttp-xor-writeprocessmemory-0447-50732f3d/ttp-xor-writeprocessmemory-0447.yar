rule TTP_XOR_WriteProcessMemory_0447 {
  strings:
    $key_0447 = { 53 35 [2] 61 17 [2] 67 22 [2] 49 22 [2] 76 3e }

  condition:
    any of them
}