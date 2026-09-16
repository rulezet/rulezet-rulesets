rule TTP_XOR_WriteProcessMemory_cd0f {
  strings:
    $key_cd0f = { 9a 7d [2] a8 5f [2] ae 6a [2] 80 6a [2] bf 76 }

  condition:
    any of them
}