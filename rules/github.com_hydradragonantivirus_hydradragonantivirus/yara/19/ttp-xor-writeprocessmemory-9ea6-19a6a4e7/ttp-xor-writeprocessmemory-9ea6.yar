rule TTP_XOR_WriteProcessMemory_9ea6 {
  strings:
    $key_9ea6 = { c9 d4 [2] fb f6 [2] fd c3 [2] d3 c3 [2] ec df }

  condition:
    any of them
}