rule TTP_XOR_WriteProcessMemory_cd7a {
  strings:
    $key_cd7a = { 9a 08 [2] a8 2a [2] ae 1f [2] 80 1f [2] bf 03 }

  condition:
    any of them
}