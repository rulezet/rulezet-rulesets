rule TTP_XOR_WriteProcessMemory_fda7 {
  strings:
    $key_fda7 = { aa d5 [2] 98 f7 [2] 9e c2 [2] b0 c2 [2] 8f de }

  condition:
    any of them
}