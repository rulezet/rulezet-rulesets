rule TTP_XOR_WriteProcessMemory_c89f {
  strings:
    $key_c89f = { 9f ed [2] ad cf [2] ab fa [2] 85 fa [2] ba e6 }

  condition:
    any of them
}