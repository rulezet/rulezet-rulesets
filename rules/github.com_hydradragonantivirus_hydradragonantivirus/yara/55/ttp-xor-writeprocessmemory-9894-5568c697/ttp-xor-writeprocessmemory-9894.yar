rule TTP_XOR_WriteProcessMemory_9894 {
  strings:
    $key_9894 = { cf e6 [2] fd c4 [2] fb f1 [2] d5 f1 [2] ea ed }

  condition:
    any of them
}