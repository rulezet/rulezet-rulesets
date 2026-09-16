rule TTP_XOR_WriteProcessMemory_d07b {
  strings:
    $key_d07b = { 87 09 [2] b5 2b [2] b3 1e [2] 9d 1e [2] a2 02 }

  condition:
    any of them
}