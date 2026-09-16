rule TTP_XOR_WriteProcessMemory_9be4 {
  strings:
    $key_9be4 = { cc 96 [2] fe b4 [2] f8 81 [2] d6 81 [2] e9 9d }

  condition:
    any of them
}