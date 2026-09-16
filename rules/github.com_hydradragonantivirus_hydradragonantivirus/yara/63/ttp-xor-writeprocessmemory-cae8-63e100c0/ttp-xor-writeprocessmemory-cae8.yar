rule TTP_XOR_WriteProcessMemory_cae8 {
  strings:
    $key_cae8 = { 9d 9a [2] af b8 [2] a9 8d [2] 87 8d [2] b8 91 }

  condition:
    any of them
}