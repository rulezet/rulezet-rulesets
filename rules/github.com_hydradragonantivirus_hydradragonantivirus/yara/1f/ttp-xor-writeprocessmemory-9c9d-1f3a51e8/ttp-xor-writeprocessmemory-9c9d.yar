rule TTP_XOR_WriteProcessMemory_9c9d {
  strings:
    $key_9c9d = { cb ef [2] f9 cd [2] ff f8 [2] d1 f8 [2] ee e4 }

  condition:
    any of them
}