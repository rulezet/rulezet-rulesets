rule TTP_XOR_WriteProcessMemory_cb4a {
  strings:
    $key_cb4a = { 9c 38 [2] ae 1a [2] a8 2f [2] 86 2f [2] b9 33 }

  condition:
    any of them
}