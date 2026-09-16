rule TTP_XOR_WriteProcessMemory_9db6 {
  strings:
    $key_9db6 = { ca c4 [2] f8 e6 [2] fe d3 [2] d0 d3 [2] ef cf }

  condition:
    any of them
}