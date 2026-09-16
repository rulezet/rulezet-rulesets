rule TTP_XOR_WriteProcessMemory_9dd6 {
  strings:
    $key_9dd6 = { ca a4 [2] f8 86 [2] fe b3 [2] d0 b3 [2] ef af }

  condition:
    any of them
}