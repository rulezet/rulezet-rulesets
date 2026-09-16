rule TTP_XOR_WriteProcessMemory_ca7b {
  strings:
    $key_ca7b = { 9d 09 [2] af 2b [2] a9 1e [2] 87 1e [2] b8 02 }

  condition:
    any of them
}