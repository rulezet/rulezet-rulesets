rule TTP_XOR_WriteProcessMemory_9db3 {
  strings:
    $key_9db3 = { ca c1 [2] f8 e3 [2] fe d6 [2] d0 d6 [2] ef ca }

  condition:
    any of them
}