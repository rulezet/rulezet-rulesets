rule TTP_XOR_WriteProcessMemory_cb3a {
  strings:
    $key_cb3a = { 9c 48 [2] ae 6a [2] a8 5f [2] 86 5f [2] b9 43 }

  condition:
    any of them
}