rule TTP_XOR_WriteProcessMemory_9ca7 {
  strings:
    $key_9ca7 = { cb d5 [2] f9 f7 [2] ff c2 [2] d1 c2 [2] ee de }

  condition:
    any of them
}