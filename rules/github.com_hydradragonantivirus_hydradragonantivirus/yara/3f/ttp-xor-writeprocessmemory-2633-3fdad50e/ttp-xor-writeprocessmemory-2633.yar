rule TTP_XOR_WriteProcessMemory_2633 {
  strings:
    $key_2633 = { 71 41 [2] 43 63 [2] 45 56 [2] 6b 56 [2] 54 4a }

  condition:
    any of them
}