rule TTP_XOR_WriteProcessMemory_f94b {
  strings:
    $key_f94b = { ae 39 [2] 9c 1b [2] 9a 2e [2] b4 2e [2] 8b 32 }

  condition:
    any of them
}