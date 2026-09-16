rule TTP_XOR_WriteProcessMemory_cb0e {
  strings:
    $key_cb0e = { 9c 7c [2] ae 5e [2] a8 6b [2] 86 6b [2] b9 77 }

  condition:
    any of them
}