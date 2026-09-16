rule TTP_XOR_WriteProcessMemory_ca3b {
  strings:
    $key_ca3b = { 9d 49 [2] af 6b [2] a9 5e [2] 87 5e [2] b8 42 }

  condition:
    any of them
}