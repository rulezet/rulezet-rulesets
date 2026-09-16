rule TTP_XOR_WriteProcessMemory_cb2e {
  strings:
    $key_cb2e = { 9c 5c [2] ae 7e [2] a8 4b [2] 86 4b [2] b9 57 }

  condition:
    any of them
}