rule TTP_XOR_WriteProcessMemory_fcb8 {
  strings:
    $key_fcb8 = { ab ca [2] 99 e8 [2] 9f dd [2] b1 dd [2] 8e c1 }

  condition:
    any of them
}