rule TTP_XOR_WriteProcessMemory_9444 {
  strings:
    $key_9444 = { c3 36 [2] f1 14 [2] f7 21 [2] d9 21 [2] e6 3d }

  condition:
    any of them
}