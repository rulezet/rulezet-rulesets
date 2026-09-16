rule TTP_XOR_WriteProcessMemory_7b64 {
  strings:
    $key_7b64 = { 2c 16 [2] 1e 34 [2] 18 01 [2] 36 01 [2] 09 1d }

  condition:
    any of them
}