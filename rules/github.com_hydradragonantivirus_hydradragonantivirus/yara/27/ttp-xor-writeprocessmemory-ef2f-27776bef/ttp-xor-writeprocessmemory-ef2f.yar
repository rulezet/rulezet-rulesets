rule TTP_XOR_WriteProcessMemory_ef2f {
  strings:
    $key_ef2f = { b8 5d [2] 8a 7f [2] 8c 4a [2] a2 4a [2] 9d 56 }

  condition:
    any of them
}