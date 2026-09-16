rule TTP_XOR_WriteProcessMemory_fb94 {
  strings:
    $key_fb94 = { ac e6 [2] 9e c4 [2] 98 f1 [2] b6 f1 [2] 89 ed }

  condition:
    any of them
}