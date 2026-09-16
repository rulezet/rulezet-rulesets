rule TTP_XOR_WriteProcessMemory_e083 {
  strings:
    $key_e083 = { b7 f1 [2] 85 d3 [2] 83 e6 [2] ad e6 [2] 92 fa }

  condition:
    any of them
}