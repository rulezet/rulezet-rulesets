rule TTP_XOR_WriteProcessMemory_9ccb {
  strings:
    $key_9ccb = { cb b9 [2] f9 9b [2] ff ae [2] d1 ae [2] ee b2 }

  condition:
    any of them
}