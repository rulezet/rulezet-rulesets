rule TTP_XOR_WriteProcessMemory_2b64 {
  strings:
    $key_2b64 = { 7c 16 [2] 4e 34 [2] 48 01 [2] 66 01 [2] 59 1d }

  condition:
    any of them
}