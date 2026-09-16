rule TTP_XOR_WriteProcessMemory_fdd3 {
  strings:
    $key_fdd3 = { aa a1 [2] 98 83 [2] 9e b6 [2] b0 b6 [2] 8f aa }

  condition:
    any of them
}