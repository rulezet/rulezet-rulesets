rule TTP_XOR_WriteProcessMemory_9403 {
  strings:
    $key_9403 = { c3 71 [2] f1 53 [2] f7 66 [2] d9 66 [2] e6 7a }

  condition:
    any of them
}