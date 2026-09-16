rule TTP_XOR_WriteProcessMemory_0b04 {
  strings:
    $key_0b04 = { 5c 76 [2] 6e 54 [2] 68 61 [2] 46 61 [2] 79 7d }

  condition:
    any of them
}