rule TTP_XOR_WriteProcessMemory_a9c4 {
  strings:
    $key_a9c4 = { fe b6 [2] cc 94 [2] ca a1 [2] e4 a1 [2] db bd }

  condition:
    any of them
}