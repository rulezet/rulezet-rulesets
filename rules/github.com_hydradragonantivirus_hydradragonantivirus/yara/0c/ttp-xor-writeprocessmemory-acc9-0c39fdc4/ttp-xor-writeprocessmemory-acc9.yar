rule TTP_XOR_WriteProcessMemory_acc9 {
  strings:
    $key_acc9 = { fb bb [2] c9 99 [2] cf ac [2] e1 ac [2] de b0 }

  condition:
    any of them
}