rule TTP_XOR_WriteProcessMemory_fdfd {
  strings:
    $key_fdfd = { aa 8f [2] 98 ad [2] 9e 98 [2] b0 98 [2] 8f 84 }

  condition:
    any of them
}