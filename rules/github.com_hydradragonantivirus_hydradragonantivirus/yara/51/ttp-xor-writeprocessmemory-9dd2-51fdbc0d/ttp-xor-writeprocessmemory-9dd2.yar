rule TTP_XOR_WriteProcessMemory_9dd2 {
  strings:
    $key_9dd2 = { ca a0 [2] f8 82 [2] fe b7 [2] d0 b7 [2] ef ab }

  condition:
    any of them
}