rule TTP_XOR_WriteProcessMemory_08fc {
  strings:
    $key_08fc = { 5f 8e [2] 6d ac [2] 6b 99 [2] 45 99 [2] 7a 85 }

  condition:
    any of them
}