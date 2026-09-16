rule TTP_XOR_WriteProcessMemory_fda3 {
  strings:
    $key_fda3 = { aa d1 [2] 98 f3 [2] 9e c6 [2] b0 c6 [2] 8f da }

  condition:
    any of them
}