rule TTP_XOR_WriteProcessMemory_9bb5 {
  strings:
    $key_9bb5 = { cc c7 [2] fe e5 [2] f8 d0 [2] d6 d0 [2] e9 cc }

  condition:
    any of them
}