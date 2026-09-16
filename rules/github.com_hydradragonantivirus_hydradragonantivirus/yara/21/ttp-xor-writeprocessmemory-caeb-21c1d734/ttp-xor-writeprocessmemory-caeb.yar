rule TTP_XOR_WriteProcessMemory_caeb {
  strings:
    $key_caeb = { 9d 99 [2] af bb [2] a9 8e [2] 87 8e [2] b8 92 }

  condition:
    any of them
}