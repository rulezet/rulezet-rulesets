rule TTP_XOR_WriteProcessMemory_9534 {
  strings:
    $key_9534 = { c2 46 [2] f0 64 [2] f6 51 [2] d8 51 [2] e7 4d }

  condition:
    any of them
}