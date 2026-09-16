rule TTP_XOR_WriteProcessMemory_4203 {
  strings:
    $key_4203 = { 15 71 [2] 27 53 [2] 21 66 [2] 0f 66 [2] 30 7a }

  condition:
    any of them
}