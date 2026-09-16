rule TTP_XOR_WriteProcessMemory_5b64 {
  strings:
    $key_5b64 = { 0c 16 [2] 3e 34 [2] 38 01 [2] 16 01 [2] 29 1d }

  condition:
    any of them
}