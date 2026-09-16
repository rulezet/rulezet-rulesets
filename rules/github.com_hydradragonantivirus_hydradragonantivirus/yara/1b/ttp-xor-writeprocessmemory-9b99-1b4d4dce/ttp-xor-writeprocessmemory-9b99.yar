rule TTP_XOR_WriteProcessMemory_9b99 {
  strings:
    $key_9b99 = { cc eb [2] fe c9 [2] f8 fc [2] d6 fc [2] e9 e0 }

  condition:
    any of them
}