rule TTP_XOR_WriteProcessMemory_9c99 {
  strings:
    $key_9c99 = { cb eb [2] f9 c9 [2] ff fc [2] d1 fc [2] ee e0 }

  condition:
    any of them
}