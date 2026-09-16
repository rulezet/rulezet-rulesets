rule TTP_XOR_WriteProcessMemory_e88f {
  strings:
    $key_e88f = { bf fd [2] 8d df [2] 8b ea [2] a5 ea [2] 9a f6 }

  condition:
    any of them
}