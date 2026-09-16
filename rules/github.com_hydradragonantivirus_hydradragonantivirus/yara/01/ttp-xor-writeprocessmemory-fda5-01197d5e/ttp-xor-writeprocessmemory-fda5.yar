rule TTP_XOR_WriteProcessMemory_fda5 {
  strings:
    $key_fda5 = { aa d7 [2] 98 f5 [2] 9e c0 [2] b0 c0 [2] 8f dc }

  condition:
    any of them
}