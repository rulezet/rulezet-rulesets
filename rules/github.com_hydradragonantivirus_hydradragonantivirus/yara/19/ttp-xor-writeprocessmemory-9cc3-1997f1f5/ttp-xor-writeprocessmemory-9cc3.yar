rule TTP_XOR_WriteProcessMemory_9cc3 {
  strings:
    $key_9cc3 = { cb b1 [2] f9 93 [2] ff a6 [2] d1 a6 [2] ee ba }

  condition:
    any of them
}