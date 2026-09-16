rule TTP_XOR_WriteProcessMemory_1ebf {
  strings:
    $key_1ebf = { 49 cd [2] 7b ef [2] 7d da [2] 53 da [2] 6c c6 }

  condition:
    any of them
}