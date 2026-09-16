rule TTP_XOR_WriteProcessMemory_cb1b {
  strings:
    $key_cb1b = { 9c 69 [2] ae 4b [2] a8 7e [2] 86 7e [2] b9 62 }

  condition:
    any of them
}