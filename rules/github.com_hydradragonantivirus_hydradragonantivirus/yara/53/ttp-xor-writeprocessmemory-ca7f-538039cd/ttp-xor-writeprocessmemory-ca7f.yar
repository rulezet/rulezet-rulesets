rule TTP_XOR_WriteProcessMemory_ca7f {
  strings:
    $key_ca7f = { 9d 0d [2] af 2f [2] a9 1a [2] 87 1a [2] b8 06 }

  condition:
    any of them
}