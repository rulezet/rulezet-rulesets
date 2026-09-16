rule TTP_XOR_WriteProcessMemory_d99f {
  strings:
    $key_d99f = { 8e ed [2] bc cf [2] ba fa [2] 94 fa [2] ab e6 }

  condition:
    any of them
}