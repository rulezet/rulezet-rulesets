rule TTP_XOR_WriteProcessMemory_d28d {
  strings:
    $key_d28d = { 85 ff [2] b7 dd [2] b1 e8 [2] 9f e8 [2] a0 f4 }

  condition:
    any of them
}