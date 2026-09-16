rule TTP_XOR_WriteProcessMemory_dc1f {
  strings:
    $key_dc1f = { 8b 6d [2] b9 4f [2] bf 7a [2] 91 7a [2] ae 66 }

  condition:
    any of them
}