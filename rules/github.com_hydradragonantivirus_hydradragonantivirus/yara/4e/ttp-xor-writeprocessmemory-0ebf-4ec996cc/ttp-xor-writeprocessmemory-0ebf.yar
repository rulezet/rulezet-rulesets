rule TTP_XOR_WriteProcessMemory_0ebf {
  strings:
    $key_0ebf = { 59 cd [2] 6b ef [2] 6d da [2] 43 da [2] 7c c6 }

  condition:
    any of them
}