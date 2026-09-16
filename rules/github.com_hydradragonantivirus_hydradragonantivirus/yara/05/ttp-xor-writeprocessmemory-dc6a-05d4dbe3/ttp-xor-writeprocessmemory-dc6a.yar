rule TTP_XOR_WriteProcessMemory_dc6a {
  strings:
    $key_dc6a = { 8b 18 [2] b9 3a [2] bf 0f [2] 91 0f [2] ae 13 }

  condition:
    any of them
}