rule TTP_XOR_WriteProcessMemory_cb0f {
  strings:
    $key_cb0f = { 9c 7d [2] ae 5f [2] a8 6a [2] 86 6a [2] b9 76 }

  condition:
    any of them
}