rule TTP_XOR_WriteProcessMemory_9890 {
  strings:
    $key_9890 = { cf e2 [2] fd c0 [2] fb f5 [2] d5 f5 [2] ea e9 }

  condition:
    any of them
}