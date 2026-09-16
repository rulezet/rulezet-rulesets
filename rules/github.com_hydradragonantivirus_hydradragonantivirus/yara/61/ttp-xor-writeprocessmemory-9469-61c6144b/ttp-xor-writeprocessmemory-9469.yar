rule TTP_XOR_WriteProcessMemory_9469 {
  strings:
    $key_9469 = { c3 1b [2] f1 39 [2] f7 0c [2] d9 0c [2] e6 10 }

  condition:
    any of them
}