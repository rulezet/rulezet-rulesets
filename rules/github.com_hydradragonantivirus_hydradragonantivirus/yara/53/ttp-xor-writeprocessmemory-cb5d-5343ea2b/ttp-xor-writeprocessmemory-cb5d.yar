rule TTP_XOR_WriteProcessMemory_cb5d {
  strings:
    $key_cb5d = { 9c 2f [2] ae 0d [2] a8 38 [2] 86 38 [2] b9 24 }

  condition:
    any of them
}