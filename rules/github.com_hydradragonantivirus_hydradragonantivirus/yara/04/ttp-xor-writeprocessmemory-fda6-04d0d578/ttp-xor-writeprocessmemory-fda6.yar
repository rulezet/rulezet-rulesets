rule TTP_XOR_WriteProcessMemory_fda6 {
  strings:
    $key_fda6 = { aa d4 [2] 98 f6 [2] 9e c3 [2] b0 c3 [2] 8f df }

  condition:
    any of them
}