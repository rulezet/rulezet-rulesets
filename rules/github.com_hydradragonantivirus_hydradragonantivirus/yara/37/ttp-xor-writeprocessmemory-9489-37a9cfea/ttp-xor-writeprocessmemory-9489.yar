rule TTP_XOR_WriteProcessMemory_9489 {
  strings:
    $key_9489 = { c3 fb [2] f1 d9 [2] f7 ec [2] d9 ec [2] e6 f0 }

  condition:
    any of them
}