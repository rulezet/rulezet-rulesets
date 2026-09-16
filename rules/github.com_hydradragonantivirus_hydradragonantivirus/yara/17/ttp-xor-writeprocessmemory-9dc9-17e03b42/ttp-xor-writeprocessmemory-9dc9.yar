rule TTP_XOR_WriteProcessMemory_9dc9 {
  strings:
    $key_9dc9 = { ca bb [2] f8 99 [2] fe ac [2] d0 ac [2] ef b0 }

  condition:
    any of them
}