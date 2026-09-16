rule TTP_XOR_WriteProcessMemory_7da6 {
  strings:
    $key_7da6 = { 2a d4 [2] 18 f6 [2] 1e c3 [2] 30 c3 [2] 0f df }

  condition:
    any of them
}