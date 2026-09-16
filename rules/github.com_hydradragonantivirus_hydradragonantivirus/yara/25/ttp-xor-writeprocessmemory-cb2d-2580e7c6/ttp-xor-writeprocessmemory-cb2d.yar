rule TTP_XOR_WriteProcessMemory_cb2d {
  strings:
    $key_cb2d = { 9c 5f [2] ae 7d [2] a8 48 [2] 86 48 [2] b9 54 }

  condition:
    any of them
}