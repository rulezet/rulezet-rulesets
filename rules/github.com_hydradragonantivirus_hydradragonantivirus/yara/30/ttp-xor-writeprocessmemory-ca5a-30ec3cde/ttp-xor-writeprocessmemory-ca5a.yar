rule TTP_XOR_WriteProcessMemory_ca5a {
  strings:
    $key_ca5a = { 9d 28 [2] af 0a [2] a9 3f [2] 87 3f [2] b8 23 }

  condition:
    any of them
}