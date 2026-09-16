rule TTP_XOR_WriteProcessMemory_cbef {
  strings:
    $key_cbef = { 9c 9d [2] ae bf [2] a8 8a [2] 86 8a [2] b9 96 }

  condition:
    any of them
}