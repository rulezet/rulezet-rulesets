rule TTP_XOR_WriteProcessMemory_cb99 {
  strings:
    $key_cb99 = { 9c eb [2] ae c9 [2] a8 fc [2] 86 fc [2] b9 e0 }

  condition:
    any of them
}