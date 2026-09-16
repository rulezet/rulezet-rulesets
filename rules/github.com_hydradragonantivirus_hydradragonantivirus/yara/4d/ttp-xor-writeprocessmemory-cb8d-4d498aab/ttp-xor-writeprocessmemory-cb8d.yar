rule TTP_XOR_WriteProcessMemory_cb8d {
  strings:
    $key_cb8d = { 9c ff [2] ae dd [2] a8 e8 [2] 86 e8 [2] b9 f4 }

  condition:
    any of them
}