rule TTP_XOR_WriteProcessMemory_dc28 {
  strings:
    $key_dc28 = { 8b 5a [2] b9 78 [2] bf 4d [2] 91 4d [2] ae 51 }

  condition:
    any of them
}