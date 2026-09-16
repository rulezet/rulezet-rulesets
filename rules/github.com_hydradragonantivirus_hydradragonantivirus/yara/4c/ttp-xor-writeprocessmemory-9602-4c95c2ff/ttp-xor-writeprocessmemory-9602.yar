rule TTP_XOR_WriteProcessMemory_9602 {
  strings:
    $key_9602 = { c1 70 [2] f3 52 [2] f5 67 [2] db 67 [2] e4 7b }

  condition:
    any of them
}