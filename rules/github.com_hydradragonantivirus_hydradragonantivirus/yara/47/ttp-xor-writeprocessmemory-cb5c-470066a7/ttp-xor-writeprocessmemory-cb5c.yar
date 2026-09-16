rule TTP_XOR_WriteProcessMemory_cb5c {
  strings:
    $key_cb5c = { 9c 2e [2] ae 0c [2] a8 39 [2] 86 39 [2] b9 25 }

  condition:
    any of them
}