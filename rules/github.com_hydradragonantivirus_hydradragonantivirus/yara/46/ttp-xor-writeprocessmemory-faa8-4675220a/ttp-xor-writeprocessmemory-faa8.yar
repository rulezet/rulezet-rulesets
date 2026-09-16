rule TTP_XOR_WriteProcessMemory_faa8 {
  strings:
    $key_faa8 = { ad da [2] 9f f8 [2] 99 cd [2] b7 cd [2] 88 d1 }

  condition:
    any of them
}