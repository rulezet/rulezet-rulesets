rule TTP_XOR_WriteProcessMemory_9cc9 {
  strings:
    $key_9cc9 = { cb bb [2] f9 99 [2] ff ac [2] d1 ac [2] ee b0 }

  condition:
    any of them
}