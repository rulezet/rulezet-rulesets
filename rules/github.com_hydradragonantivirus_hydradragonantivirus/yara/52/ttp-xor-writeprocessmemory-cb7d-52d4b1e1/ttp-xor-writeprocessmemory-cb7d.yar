rule TTP_XOR_WriteProcessMemory_cb7d {
  strings:
    $key_cb7d = { 9c 0f [2] ae 2d [2] a8 18 [2] 86 18 [2] b9 04 }

  condition:
    any of them
}