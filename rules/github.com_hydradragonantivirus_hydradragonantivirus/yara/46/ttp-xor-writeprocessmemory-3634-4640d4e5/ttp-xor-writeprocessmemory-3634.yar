rule TTP_XOR_WriteProcessMemory_3634 {
  strings:
    $key_3634 = { 61 46 [2] 53 64 [2] 55 51 [2] 7b 51 [2] 44 4d }

  condition:
    any of them
}