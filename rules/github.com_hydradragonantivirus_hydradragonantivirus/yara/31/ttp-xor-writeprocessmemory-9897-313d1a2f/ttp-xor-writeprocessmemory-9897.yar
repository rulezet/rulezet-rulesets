rule TTP_XOR_WriteProcessMemory_9897 {
  strings:
    $key_9897 = { cf e5 [2] fd c7 [2] fb f2 [2] d5 f2 [2] ea ee }

  condition:
    any of them
}