rule TTP_XOR_WriteProcessMemory_9186 {
  strings:
    $key_9186 = { c6 f4 [2] f4 d6 [2] f2 e3 [2] dc e3 [2] e3 ff }

  condition:
    any of them
}