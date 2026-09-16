rule TTP_XOR_WriteProcessMemory_fb19 {
  strings:
    $key_fb19 = { ac 6b [2] 9e 49 [2] 98 7c [2] b6 7c [2] 89 60 }

  condition:
    any of them
}