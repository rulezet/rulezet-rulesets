rule TTP_XOR_WriteProcessMemory_d89f {
  strings:
    $key_d89f = { 8f ed [2] bd cf [2] bb fa [2] 95 fa [2] aa e6 }

  condition:
    any of them
}