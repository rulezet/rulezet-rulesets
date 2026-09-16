rule TTP_XOR_WriteProcessMemory_26fc {
  strings:
    $key_26fc = { 71 8e [2] 43 ac [2] 45 99 [2] 6b 99 [2] 54 85 }

  condition:
    any of them
}