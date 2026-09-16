rule TTP_XOR_WriteProcessMemory_dd86 {
  strings:
    $key_dd86 = { 8a f4 [2] b8 d6 [2] be e3 [2] 90 e3 [2] af ff }

  condition:
    any of them
}