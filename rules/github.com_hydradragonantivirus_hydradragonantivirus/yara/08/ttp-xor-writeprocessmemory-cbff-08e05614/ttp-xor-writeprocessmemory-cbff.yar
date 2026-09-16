rule TTP_XOR_WriteProcessMemory_cbff {
  strings:
    $key_cbff = { 9c 8d [2] ae af [2] a8 9a [2] 86 9a [2] b9 86 }

  condition:
    any of them
}