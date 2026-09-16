rule TTP_XOR_WriteProcessMemory_3125 {
  strings:
    $key_3125 = { 66 57 [2] 54 75 [2] 52 40 [2] 7c 40 [2] 43 5c }

  condition:
    any of them
}