rule TTP_XOR_WriteProcessMemory_9bb6 {
  strings:
    $key_9bb6 = { cc c4 [2] fe e6 [2] f8 d3 [2] d6 d3 [2] e9 cf }

  condition:
    any of them
}