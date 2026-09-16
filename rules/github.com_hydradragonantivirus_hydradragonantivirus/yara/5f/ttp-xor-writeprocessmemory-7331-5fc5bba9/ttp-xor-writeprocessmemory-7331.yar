rule TTP_XOR_WriteProcessMemory_7331 {
  strings:
    $key_7331 = { 24 43 [2] 16 61 [2] 10 54 [2] 3e 54 [2] 01 48 }

  condition:
    any of them
}