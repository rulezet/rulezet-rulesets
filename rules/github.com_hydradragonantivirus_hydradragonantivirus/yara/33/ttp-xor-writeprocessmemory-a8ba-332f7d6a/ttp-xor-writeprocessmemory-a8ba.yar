rule TTP_XOR_WriteProcessMemory_a8ba {
  strings:
    $key_a8ba = { ff c8 [2] cd ea [2] cb df [2] e5 df [2] da c3 }

  condition:
    any of them
}