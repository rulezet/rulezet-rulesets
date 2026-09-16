rule TTP_XOR_WriteProcessMemory_2634 {
  strings:
    $key_2634 = { 71 46 [2] 43 64 [2] 45 51 [2] 6b 51 [2] 54 4d }

  condition:
    any of them
}