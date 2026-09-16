rule TTP_XOR_WriteProcessMemory_fde5 {
  strings:
    $key_fde5 = { aa 97 [2] 98 b5 [2] 9e 80 [2] b0 80 [2] 8f 9c }

  condition:
    any of them
}