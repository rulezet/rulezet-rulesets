rule TTP_XOR_WriteProcessMemory_9ca4 {
  strings:
    $key_9ca4 = { cb d6 [2] f9 f4 [2] ff c1 [2] d1 c1 [2] ee dd }

  condition:
    any of them
}