rule TTP_XOR_WriteProcessMemory_dcff {
  strings:
    $key_dcff = { 8b 8d [2] b9 af [2] bf 9a [2] 91 9a [2] ae 86 }

  condition:
    any of them
}