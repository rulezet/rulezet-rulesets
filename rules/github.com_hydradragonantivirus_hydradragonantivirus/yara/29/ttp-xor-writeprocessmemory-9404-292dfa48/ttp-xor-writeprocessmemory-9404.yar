rule TTP_XOR_WriteProcessMemory_9404 {
  strings:
    $key_9404 = { c3 76 [2] f1 54 [2] f7 61 [2] d9 61 [2] e6 7d }

  condition:
    any of them
}