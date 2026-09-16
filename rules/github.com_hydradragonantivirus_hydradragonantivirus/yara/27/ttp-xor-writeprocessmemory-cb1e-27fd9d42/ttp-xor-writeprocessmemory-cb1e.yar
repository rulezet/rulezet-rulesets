rule TTP_XOR_WriteProcessMemory_cb1e {
  strings:
    $key_cb1e = { 9c 6c [2] ae 4e [2] a8 7b [2] 86 7b [2] b9 67 }

  condition:
    any of them
}