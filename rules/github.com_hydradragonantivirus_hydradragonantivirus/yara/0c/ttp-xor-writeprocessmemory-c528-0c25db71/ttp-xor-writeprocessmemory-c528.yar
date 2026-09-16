rule TTP_XOR_WriteProcessMemory_c528 {
  strings:
    $key_c528 = { 92 5a [2] a0 78 [2] a6 4d [2] 88 4d [2] b7 51 }

  condition:
    any of them
}