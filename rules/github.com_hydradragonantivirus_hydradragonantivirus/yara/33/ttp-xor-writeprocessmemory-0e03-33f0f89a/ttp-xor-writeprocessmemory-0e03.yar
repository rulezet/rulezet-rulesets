rule TTP_XOR_WriteProcessMemory_0e03 {
  strings:
    $key_0e03 = { 59 71 [2] 6b 53 [2] 6d 66 [2] 43 66 [2] 7c 7a }

  condition:
    any of them
}