rule TTP_XOR_WriteProcessMemory_9da5 {
  strings:
    $key_9da5 = { ca d7 [2] f8 f5 [2] fe c0 [2] d0 c0 [2] ef dc }

  condition:
    any of them
}