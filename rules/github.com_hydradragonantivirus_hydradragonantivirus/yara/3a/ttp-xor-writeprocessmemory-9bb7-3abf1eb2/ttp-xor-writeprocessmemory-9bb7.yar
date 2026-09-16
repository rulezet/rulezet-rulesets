rule TTP_XOR_WriteProcessMemory_9bb7 {
  strings:
    $key_9bb7 = { cc c5 [2] fe e7 [2] f8 d2 [2] d6 d2 [2] e9 ce }

  condition:
    any of them
}