rule TTP_XOR_WriteProcessMemory_bcc9 {
  strings:
    $key_bcc9 = { eb bb [2] d9 99 [2] df ac [2] f1 ac [2] ce b0 }

  condition:
    any of them
}