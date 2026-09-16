rule TTP_XOR_WriteProcessMemory_4b64 {
  strings:
    $key_4b64 = { 1c 16 [2] 2e 34 [2] 28 01 [2] 06 01 [2] 39 1d }

  condition:
    any of them
}