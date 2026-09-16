rule TTP_XOR_WriteProcessMemory_dc5f {
  strings:
    $key_dc5f = { 8b 2d [2] b9 0f [2] bf 3a [2] 91 3a [2] ae 26 }

  condition:
    any of them
}