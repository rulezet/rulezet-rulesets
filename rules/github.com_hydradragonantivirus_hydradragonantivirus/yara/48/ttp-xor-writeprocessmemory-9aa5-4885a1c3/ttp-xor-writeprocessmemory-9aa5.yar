rule TTP_XOR_WriteProcessMemory_9aa5 {
  strings:
    $key_9aa5 = { cd d7 [2] ff f5 [2] f9 c0 [2] d7 c0 [2] e8 dc }

  condition:
    any of them
}