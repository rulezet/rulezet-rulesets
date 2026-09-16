rule TTP_XOR_WriteProcessMemory_f9fb {
  strings:
    $key_f9fb = { ae 89 [2] 9c ab [2] 9a 9e [2] b4 9e [2] 8b 82 }

  condition:
    any of them
}