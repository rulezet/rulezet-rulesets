rule TTP_XOR_WriteProcessMemory_0b64 {
  strings:
    $key_0b64 = { 5c 16 [2] 6e 34 [2] 68 01 [2] 46 01 [2] 79 1d }

  condition:
    any of them
}