rule TTP_XOR_WriteProcessMemory_9be0 {
  strings:
    $key_9be0 = { cc 92 [2] fe b0 [2] f8 85 [2] d6 85 [2] e9 99 }

  condition:
    any of them
}