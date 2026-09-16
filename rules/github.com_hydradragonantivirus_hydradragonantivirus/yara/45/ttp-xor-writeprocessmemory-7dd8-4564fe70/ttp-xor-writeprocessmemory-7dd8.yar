rule TTP_XOR_WriteProcessMemory_7dd8 {
  strings:
    $key_7dd8 = { 2a aa [2] 18 88 [2] 1e bd [2] 30 bd [2] 0f a1 }

  condition:
    any of them
}