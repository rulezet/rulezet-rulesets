rule TTP_XOR_WriteProcessMemory_9bc7 {
  strings:
    $key_9bc7 = { cc b5 [2] fe 97 [2] f8 a2 [2] d6 a2 [2] e9 be }

  condition:
    any of them
}