rule TTP_XOR_WriteProcessMemory_3133 {
  strings:
    $key_3133 = { 66 41 [2] 54 63 [2] 52 56 [2] 7c 56 [2] 43 4a }

  condition:
    any of them
}