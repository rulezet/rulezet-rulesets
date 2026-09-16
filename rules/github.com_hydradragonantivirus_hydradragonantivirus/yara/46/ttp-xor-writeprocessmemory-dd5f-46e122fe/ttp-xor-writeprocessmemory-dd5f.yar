rule TTP_XOR_WriteProcessMemory_dd5f {
  strings:
    $key_dd5f = { 8a 2d [2] b8 0f [2] be 3a [2] 90 3a [2] af 26 }

  condition:
    any of them
}