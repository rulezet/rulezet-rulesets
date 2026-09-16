rule TTP_XOR_WriteProcessMemory_ca5f {
  strings:
    $key_ca5f = { 9d 2d [2] af 0f [2] a9 3a [2] 87 3a [2] b8 26 }

  condition:
    any of them
}