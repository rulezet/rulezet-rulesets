rule TTP_XOR_WriteProcessMemory_fda4 {
  strings:
    $key_fda4 = { aa d6 [2] 98 f4 [2] 9e c1 [2] b0 c1 [2] 8f dd }

  condition:
    any of them
}