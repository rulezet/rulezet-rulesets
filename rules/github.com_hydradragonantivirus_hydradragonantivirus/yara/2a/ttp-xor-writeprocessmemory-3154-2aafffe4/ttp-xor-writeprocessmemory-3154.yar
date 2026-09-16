rule TTP_XOR_WriteProcessMemory_3154 {
  strings:
    $key_3154 = { 66 26 [2] 54 04 [2] 52 31 [2] 7c 31 [2] 43 2d }

  condition:
    any of them
}