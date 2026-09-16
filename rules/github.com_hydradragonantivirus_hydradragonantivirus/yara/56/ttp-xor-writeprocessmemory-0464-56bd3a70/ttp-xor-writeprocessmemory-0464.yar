rule TTP_XOR_WriteProcessMemory_0464 {
  strings:
    $key_0464 = { 53 16 [2] 61 34 [2] 67 01 [2] 49 01 [2] 76 1d }

  condition:
    any of them
}