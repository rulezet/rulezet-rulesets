rule TTP_XOR_WriteProcessMemory_3b03 {
  strings:
    $key_3b03 = { 6c 71 [2] 5e 53 [2] 58 66 [2] 76 66 [2] 49 7a }

  condition:
    any of them
}