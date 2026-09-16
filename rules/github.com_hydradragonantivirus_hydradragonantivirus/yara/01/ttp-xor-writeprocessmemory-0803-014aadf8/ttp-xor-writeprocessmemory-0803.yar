rule TTP_XOR_WriteProcessMemory_0803 {
  strings:
    $key_0803 = { 5f 71 [2] 6d 53 [2] 6b 66 [2] 45 66 [2] 7a 7a }

  condition:
    any of them
}