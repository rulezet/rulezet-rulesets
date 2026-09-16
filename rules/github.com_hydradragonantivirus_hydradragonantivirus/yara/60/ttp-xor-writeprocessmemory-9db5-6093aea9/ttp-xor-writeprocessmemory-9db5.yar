rule TTP_XOR_WriteProcessMemory_9db5 {
  strings:
    $key_9db5 = { ca c7 [2] f8 e5 [2] fe d0 [2] d0 d0 [2] ef cc }

  condition:
    any of them
}