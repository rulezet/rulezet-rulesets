rule TTP_XOR_WriteProcessMemory_9dd7 {
  strings:
    $key_9dd7 = { ca a5 [2] f8 87 [2] fe b2 [2] d0 b2 [2] ef ae }

  condition:
    any of them
}