rule TTP_XOR_WriteProcessMemory_dc6f {
  strings:
    $key_dc6f = { 8b 1d [2] b9 3f [2] bf 0a [2] 91 0a [2] ae 16 }

  condition:
    any of them
}