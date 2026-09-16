rule TTP_XOR_WriteProcessMemory_9d99 {
  strings:
    $key_9d99 = { ca eb [2] f8 c9 [2] fe fc [2] d0 fc [2] ef e0 }

  condition:
    any of them
}