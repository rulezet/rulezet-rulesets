rule TTP_XOR_WriteProcessMemory_cd1a {
  strings:
    $key_cd1a = { 9a 68 [2] a8 4a [2] ae 7f [2] 80 7f [2] bf 63 }

  condition:
    any of them
}