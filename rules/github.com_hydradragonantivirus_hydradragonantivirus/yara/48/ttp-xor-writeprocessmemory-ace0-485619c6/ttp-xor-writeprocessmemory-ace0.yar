rule TTP_XOR_WriteProcessMemory_ace0 {
  strings:
    $key_ace0 = { fb 92 [2] c9 b0 [2] cf 85 [2] e1 85 [2] de 99 }

  condition:
    any of them
}