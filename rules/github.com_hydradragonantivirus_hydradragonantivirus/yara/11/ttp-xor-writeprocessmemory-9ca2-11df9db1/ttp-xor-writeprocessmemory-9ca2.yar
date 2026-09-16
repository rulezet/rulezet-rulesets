rule TTP_XOR_WriteProcessMemory_9ca2 {
  strings:
    $key_9ca2 = { cb d0 [2] f9 f2 [2] ff c7 [2] d1 c7 [2] ee db }

  condition:
    any of them
}