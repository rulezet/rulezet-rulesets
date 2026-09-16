rule TTP_XOR_WriteProcessMemory_9bb3 {
  strings:
    $key_9bb3 = { cc c1 [2] fe e3 [2] f8 d6 [2] d6 d6 [2] e9 ca }

  condition:
    any of them
}