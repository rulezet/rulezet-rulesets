rule TTP_XOR_WriteProcessMemory_cd7d {
  strings:
    $key_cd7d = { 9a 0f [2] a8 2d [2] ae 18 [2] 80 18 [2] bf 04 }

  condition:
    any of them
}