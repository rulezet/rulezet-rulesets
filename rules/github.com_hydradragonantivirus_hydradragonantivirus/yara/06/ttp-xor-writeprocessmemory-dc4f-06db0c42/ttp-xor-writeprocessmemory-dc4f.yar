rule TTP_XOR_WriteProcessMemory_dc4f {
  strings:
    $key_dc4f = { 8b 3d [2] b9 1f [2] bf 2a [2] 91 2a [2] ae 36 }

  condition:
    any of them
}