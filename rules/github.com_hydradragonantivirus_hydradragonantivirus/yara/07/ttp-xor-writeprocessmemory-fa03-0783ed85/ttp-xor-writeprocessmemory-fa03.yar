rule TTP_XOR_WriteProcessMemory_fa03 {
  strings:
    $key_fa03 = { ad 71 [2] 9f 53 [2] 99 66 [2] b7 66 [2] 88 7a }

  condition:
    any of them
}