rule TTP_XOR_WriteProcessMemory_f48f {
  strings:
    $key_f48f = { a3 fd [2] 91 df [2] 97 ea [2] b9 ea [2] 86 f6 }

  condition:
    any of them
}