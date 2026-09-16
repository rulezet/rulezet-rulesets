rule TTP_XOR_WriteProcessMemory_2234 {
  strings:
    $key_2234 = { 75 46 [2] 47 64 [2] 41 51 [2] 6f 51 [2] 50 4d }

  condition:
    any of them
}