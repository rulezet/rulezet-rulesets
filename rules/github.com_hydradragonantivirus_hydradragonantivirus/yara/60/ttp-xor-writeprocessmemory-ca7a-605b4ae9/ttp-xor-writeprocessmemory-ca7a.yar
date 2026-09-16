rule TTP_XOR_WriteProcessMemory_ca7a {
  strings:
    $key_ca7a = { 9d 08 [2] af 2a [2] a9 1f [2] 87 1f [2] b8 03 }

  condition:
    any of them
}