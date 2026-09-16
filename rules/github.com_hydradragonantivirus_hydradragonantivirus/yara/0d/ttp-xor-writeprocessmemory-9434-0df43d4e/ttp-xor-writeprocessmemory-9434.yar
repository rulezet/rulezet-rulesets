rule TTP_XOR_WriteProcessMemory_9434 {
  strings:
    $key_9434 = { c3 46 [2] f1 64 [2] f7 51 [2] d9 51 [2] e6 4d }

  condition:
    any of them
}