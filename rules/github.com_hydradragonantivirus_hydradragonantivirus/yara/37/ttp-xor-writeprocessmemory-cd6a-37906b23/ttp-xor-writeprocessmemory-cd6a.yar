rule TTP_XOR_WriteProcessMemory_cd6a {
  strings:
    $key_cd6a = { 9a 18 [2] a8 3a [2] ae 0f [2] 80 0f [2] bf 13 }

  condition:
    any of them
}