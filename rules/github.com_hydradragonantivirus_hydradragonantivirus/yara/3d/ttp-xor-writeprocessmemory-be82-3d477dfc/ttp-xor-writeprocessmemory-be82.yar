rule TTP_XOR_WriteProcessMemory_be82 {
  strings:
    $key_be82 = { e9 f0 [2] db d2 [2] dd e7 [2] f3 e7 [2] cc fb }

  condition:
    any of them
}