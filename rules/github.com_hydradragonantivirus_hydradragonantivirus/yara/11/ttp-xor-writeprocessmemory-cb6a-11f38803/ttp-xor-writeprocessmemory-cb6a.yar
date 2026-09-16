rule TTP_XOR_WriteProcessMemory_cb6a {
  strings:
    $key_cb6a = { 9c 18 [2] ae 3a [2] a8 0f [2] 86 0f [2] b9 13 }

  condition:
    any of them
}