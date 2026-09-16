rule TTP_XOR_WriteProcessMemory_dc03 {
  strings:
    $key_dc03 = { 8b 71 [2] b9 53 [2] bf 66 [2] 91 66 [2] ae 7a }

  condition:
    any of them
}