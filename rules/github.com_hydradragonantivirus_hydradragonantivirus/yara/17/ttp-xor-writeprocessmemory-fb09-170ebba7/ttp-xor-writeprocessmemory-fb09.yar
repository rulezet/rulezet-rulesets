rule TTP_XOR_WriteProcessMemory_fb09 {
  strings:
    $key_fb09 = { ac 7b [2] 9e 59 [2] 98 6c [2] b6 6c [2] 89 70 }

  condition:
    any of them
}