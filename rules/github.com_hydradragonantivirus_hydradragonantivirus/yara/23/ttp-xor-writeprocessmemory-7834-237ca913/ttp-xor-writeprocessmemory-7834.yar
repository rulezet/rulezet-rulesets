rule TTP_XOR_WriteProcessMemory_7834 {
  strings:
    $key_7834 = { 2f 46 [2] 1d 64 [2] 1b 51 [2] 35 51 [2] 0a 4d }

  condition:
    any of them
}