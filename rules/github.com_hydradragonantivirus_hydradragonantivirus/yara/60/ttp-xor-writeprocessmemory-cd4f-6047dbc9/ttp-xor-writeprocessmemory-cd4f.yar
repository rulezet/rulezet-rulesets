rule TTP_XOR_WriteProcessMemory_cd4f {
  strings:
    $key_cd4f = { 9a 3d [2] a8 1f [2] ae 2a [2] 80 2a [2] bf 36 }

  condition:
    any of them
}