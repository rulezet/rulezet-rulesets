rule TTP_XOR_WriteProcessMemory_f55b {
  strings:
    $key_f55b = { a2 29 [2] 90 0b [2] 96 3e [2] b8 3e [2] 87 22 }

  condition:
    any of them
}