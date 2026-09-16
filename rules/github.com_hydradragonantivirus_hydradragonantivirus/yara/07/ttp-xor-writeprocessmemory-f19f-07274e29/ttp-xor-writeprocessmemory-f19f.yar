rule TTP_XOR_WriteProcessMemory_f19f {
  strings:
    $key_f19f = { a6 ed [2] 94 cf [2] 92 fa [2] bc fa [2] 83 e6 }

  condition:
    any of them
}