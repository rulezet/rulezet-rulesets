rule TTP_XOR_WriteProcessMemory_9ca3 {
  strings:
    $key_9ca3 = { cb d1 [2] f9 f3 [2] ff c6 [2] d1 c6 [2] ee da }

  condition:
    any of them
}