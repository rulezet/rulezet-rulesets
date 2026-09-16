rule TTP_XOR_WriteProcessMemory_fdac {
  strings:
    $key_fdac = { aa de [2] 98 fc [2] 9e c9 [2] b0 c9 [2] 8f d5 }

  condition:
    any of them
}