rule TTP_XOR_WriteProcessMemory_cc5f {
  strings:
    $key_cc5f = { 9b 2d [2] a9 0f [2] af 3a [2] 81 3a [2] be 26 }

  condition:
    any of them
}