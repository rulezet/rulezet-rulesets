rule TTP_XOR_WriteProcessMemory_ace8 {
  strings:
    $key_ace8 = { fb 9a [2] c9 b8 [2] cf 8d [2] e1 8d [2] de 91 }

  condition:
    any of them
}