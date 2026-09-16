rule TTP_XOR_WriteProcessMemory_9be8 {
  strings:
    $key_9be8 = { cc 9a [2] fe b8 [2] f8 8d [2] d6 8d [2] e9 91 }

  condition:
    any of them
}