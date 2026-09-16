rule TTP_XOR_WriteProcessMemory_0444 {
  strings:
    $key_0444 = { 53 36 [2] 61 14 [2] 67 21 [2] 49 21 [2] 76 3d }

  condition:
    any of them
}