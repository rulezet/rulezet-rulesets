rule TTP_XOR_WriteProcessMemory_cb8a {
  strings:
    $key_cb8a = { 9c f8 [2] ae da [2] a8 ef [2] 86 ef [2] b9 f3 }

  condition:
    any of them
}