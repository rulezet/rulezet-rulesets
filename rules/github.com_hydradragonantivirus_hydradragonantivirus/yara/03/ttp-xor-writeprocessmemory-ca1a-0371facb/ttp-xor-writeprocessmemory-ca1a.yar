rule TTP_XOR_WriteProcessMemory_ca1a {
  strings:
    $key_ca1a = { 9d 68 [2] af 4a [2] a9 7f [2] 87 7f [2] b8 63 }

  condition:
    any of them
}