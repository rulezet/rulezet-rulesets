rule TTP_XOR_WriteProcessMemory_1164 {
  strings:
    $key_1164 = { 46 16 [2] 74 34 [2] 72 01 [2] 5c 01 [2] 63 1d }

  condition:
    any of them
}