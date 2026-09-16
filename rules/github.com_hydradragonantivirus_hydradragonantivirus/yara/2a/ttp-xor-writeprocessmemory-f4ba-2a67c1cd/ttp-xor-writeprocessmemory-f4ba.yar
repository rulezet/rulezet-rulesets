rule TTP_XOR_WriteProcessMemory_f4ba {
  strings:
    $key_f4ba = { a3 c8 [2] 91 ea [2] 97 df [2] b9 df [2] 86 c3 }

  condition:
    any of them
}