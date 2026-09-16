rule TTP_XOR_WriteProcessMemory_9bc9 {
  strings:
    $key_9bc9 = { cc bb [2] fe 99 [2] f8 ac [2] d6 ac [2] e9 b0 }

  condition:
    any of them
}