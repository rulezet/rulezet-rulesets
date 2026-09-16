rule TTP_XOR_WriteProcessMemory_9cc7 {
  strings:
    $key_9cc7 = { cb b5 [2] f9 97 [2] ff a2 [2] d1 a2 [2] ee be }

  condition:
    any of them
}