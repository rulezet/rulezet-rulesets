rule TTP_XOR_WriteProcessMemory_cb5b {
  strings:
    $key_cb5b = { 9c 29 [2] ae 0b [2] a8 3e [2] 86 3e [2] b9 22 }

  condition:
    any of them
}