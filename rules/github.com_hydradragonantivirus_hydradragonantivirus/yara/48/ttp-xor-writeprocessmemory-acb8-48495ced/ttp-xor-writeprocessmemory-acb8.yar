rule TTP_XOR_WriteProcessMemory_acb8 {
  strings:
    $key_acb8 = { fb ca [2] c9 e8 [2] cf dd [2] e1 dd [2] de c1 }

  condition:
    any of them
}