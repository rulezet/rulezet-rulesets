rule TTP_XOR_WriteProcessMemory_4ebf {
  strings:
    $key_4ebf = { 19 cd [2] 2b ef [2] 2d da [2] 03 da [2] 3c c6 }

  condition:
    any of them
}