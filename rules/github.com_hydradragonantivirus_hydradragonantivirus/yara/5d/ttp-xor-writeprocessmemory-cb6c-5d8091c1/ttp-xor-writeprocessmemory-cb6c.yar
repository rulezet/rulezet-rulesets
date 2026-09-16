rule TTP_XOR_WriteProcessMemory_cb6c {
  strings:
    $key_cb6c = { 9c 1e [2] ae 3c [2] a8 09 [2] 86 09 [2] b9 15 }

  condition:
    any of them
}