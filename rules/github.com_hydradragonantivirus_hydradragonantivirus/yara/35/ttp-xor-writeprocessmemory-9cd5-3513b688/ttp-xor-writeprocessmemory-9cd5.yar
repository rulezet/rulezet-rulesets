rule TTP_XOR_WriteProcessMemory_9cd5 {
  strings:
    $key_9cd5 = { cb a7 [2] f9 85 [2] ff b0 [2] d1 b0 [2] ee ac }

  condition:
    any of them
}