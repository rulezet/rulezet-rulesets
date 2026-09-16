rule TTP_XOR_WriteProcessMemory_cb3c {
  strings:
    $key_cb3c = { 9c 4e [2] ae 6c [2] a8 59 [2] 86 59 [2] b9 45 }

  condition:
    any of them
}