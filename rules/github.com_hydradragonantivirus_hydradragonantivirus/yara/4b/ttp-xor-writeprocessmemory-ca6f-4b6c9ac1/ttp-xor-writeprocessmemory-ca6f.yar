rule TTP_XOR_WriteProcessMemory_ca6f {
  strings:
    $key_ca6f = { 9d 1d [2] af 3f [2] a9 0a [2] 87 0a [2] b8 16 }

  condition:
    any of them
}