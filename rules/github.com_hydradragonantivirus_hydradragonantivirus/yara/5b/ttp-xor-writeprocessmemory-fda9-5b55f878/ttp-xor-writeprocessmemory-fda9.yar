rule TTP_XOR_WriteProcessMemory_fda9 {
  strings:
    $key_fda9 = { aa db [2] 98 f9 [2] 9e cc [2] b0 cc [2] 8f d0 }

  condition:
    any of them
}