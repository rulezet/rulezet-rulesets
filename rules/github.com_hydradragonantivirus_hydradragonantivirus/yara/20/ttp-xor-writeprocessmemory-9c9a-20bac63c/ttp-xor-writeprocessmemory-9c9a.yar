rule TTP_XOR_WriteProcessMemory_9c9a {
  strings:
    $key_9c9a = { cb e8 [2] f9 ca [2] ff ff [2] d1 ff [2] ee e3 }

  condition:
    any of them
}