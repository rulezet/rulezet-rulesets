rule TTP_XOR_WriteProcessMemory_cb7a {
  strings:
    $key_cb7a = { 9c 08 [2] ae 2a [2] a8 1f [2] 86 1f [2] b9 03 }

  condition:
    any of them
}