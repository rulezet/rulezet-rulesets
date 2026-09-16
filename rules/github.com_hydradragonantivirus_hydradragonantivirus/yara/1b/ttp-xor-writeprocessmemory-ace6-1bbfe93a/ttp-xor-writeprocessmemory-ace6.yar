rule TTP_XOR_WriteProcessMemory_ace6 {
  strings:
    $key_ace6 = { fb 94 [2] c9 b6 [2] cf 83 [2] e1 83 [2] de 9f }

  condition:
    any of them
}