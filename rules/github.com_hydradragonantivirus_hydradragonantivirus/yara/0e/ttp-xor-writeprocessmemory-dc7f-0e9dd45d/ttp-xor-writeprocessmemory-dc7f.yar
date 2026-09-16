rule TTP_XOR_WriteProcessMemory_dc7f {
  strings:
    $key_dc7f = { 8b 0d [2] b9 2f [2] bf 1a [2] 91 1a [2] ae 06 }

  condition:
    any of them
}