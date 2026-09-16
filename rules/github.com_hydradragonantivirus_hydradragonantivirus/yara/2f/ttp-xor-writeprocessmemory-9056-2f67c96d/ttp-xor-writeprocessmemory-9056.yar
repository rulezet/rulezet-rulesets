rule TTP_XOR_WriteProcessMemory_9056 {
  strings:
    $key_9056 = { c7 24 [2] f5 06 [2] f3 33 [2] dd 33 [2] e2 2f }

  condition:
    any of them
}