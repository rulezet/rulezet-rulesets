rule TTP_XOR_WriteProcessMemory_ffce {
  strings:
    $key_ffce = { a8 bc [2] 9a 9e [2] 9c ab [2] b2 ab [2] 8d b7 }

  condition:
    any of them
}